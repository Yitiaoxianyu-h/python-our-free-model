"""LobsterAI（有道龙虾）渠道。

移植自原版 channel-pack 的 ``lobsterai.ts`` / ``lobsterai-adapter.ts`` /
``lobsterai-auth.ts`` / ``lobsterai-oauth.ts`` / ``lobsterai-product.ts`` /
``lobsterai-errors.ts``（SSE 解析走 ``sse.ts`` 的语义，由 ``..stream.read_stream`` 承担）：

- 登录：本地回调服务器收 ``code`` → ``POST {apiBase}/api/auth/exchange``（**不带 Authorization**）；
- 续期：``POST {apiBase}/api/auth/refresh``，请求体除 ``refreshToken`` 外还必须带
  ``firstKeyfrom`` / ``latestKeyfrom`` / ``version``（+ 可选 ``uuid`` / ``userId``），
  这三个身份字段随凭据持久化，丢了就只能重新登录；
- 推理：``POST {apiBase}/api/proxy/v1/chat/completions``，``Bearer`` 鉴权，
  ``stream`` **恒为 true**（上游只支持 SSE，``stream:false`` 返回 500）；
- 模型目录：``GET {apiBase}/api/models/available`` + keyfrom query，
  ``X-LobsterAI-Client-Capabilities`` 是**准入条件**（不带时 ``kimi-k3`` 不返回）；
- 统一信封 ``{code, msg, data}``：``code !== 0`` 即失败，``data`` 非对象也算失败
  （凭据失效时上游倾向返回 ``code:0`` + ``data:null``）；chat 端点是唯一例外（裸 SSE）。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
import uuid
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import finish_reason, read_stream

CHANNEL_ID = "lobsterai"

# ── 端点与产品常量（lobsterai.ts / lobsterai-product.ts） ────────────────────

API_BASE = "https://lobsterai-server.youdao.com"
PORTAL_BASE = "https://lobsterai.youdao.com"
CLIENT_VERSION_API = "https://api-overmind.youdao.com/openapi/get/luna/hardware/lobsterai/prod/update"

EXCHANGE_PATH = "/api/auth/exchange"
REFRESH_PATH = "/api/auth/refresh"
MODELS_PATH = "/api/models/available"
CHAT_PATH = "/api/proxy/v1/chat/completions"
CALLBACK_PATH = "/auth/callback"

USER_AGENT = "LobsterAI/0.1.0"
CLIENT_CAPABILITIES = "kimi-k3-agentic-v1,thinking-level-control-v1"
FALLBACK_CLIENT_VERSION = "2026.9.4"
VERSION_CACHE_TTL_S = 12 * 60 * 60

REQUEST_TIMEOUT_S = 30.0
LOGIN_TIMEOUT_S = 10 * 60
STREAM_TIMEOUT_S = 600.0

#: 兜底模型目录（``lobsterai-product.ts`` 的 19 条，顺序照抄原表）。
FALLBACK_MODELS: list[dict] = [
    {"id": "deepseek-v4-flash", "name": "deepseek-v4-flash"},
    {"id": "deepseek-v4-pro", "name": "deepseek-v4-pro"},
    {"id": "MiniMax-M3", "name": "MiniMax-M3"},
    {"id": "MiniMax-M2.7", "name": "MiniMax-M2.7"},
    {"id": "qwen3.7-max", "name": "qwen3.7-max"},
    {"id": "qwen3.7-plus", "name": "qwen3.7-plus"},
    {"id": "qwen3.6-plus", "name": "qwen3.6-plus"},
    {"id": "qwen3.5-plus-2026-04-20", "name": "qwen3.5-plus-2026-04-20"},
    {"id": "kimi-k2.7-code", "name": "kimi-k2.7-code"},
    {"id": "kimi-k2.7-code-highspeed", "name": "kimi-k2.7-code-highspeed"},
    {"id": "kimi-k2.6", "name": "kimi-k2.6"},
    {"id": "kimi-k2.5", "name": "kimi-k2.5"},
    {"id": "doubao-seed-2-1-pro-260628", "name": "doubao-seed-2-1-pro-260628"},
    {"id": "doubao-seed-2-1-turbo-260628", "name": "doubao-seed-2-1-turbo-260628"},
    {"id": "doubao-seed-2-0-code-preview-260215", "name": "doubao-seed-2-0-code-preview-260215"},
    {"id": "glm-5.2", "name": "glm-5.2"},
    {"id": "glm-5.1", "name": "glm-5.1"},
    {"id": "glm-5v-turbo", "name": "glm-5v-turbo"},
    {"id": "glm-5", "name": "glm-5"},
]

#: 兜底上下文窗口（桥接层的估计值，非远端权威值）。
CONTEXT_WINDOWS = {model["id"]: 131_072 for model in FALLBACK_MODELS}

# ── 错误分类（lobsterai-errors.ts） ─────────────────────────────────────────

HARD_CREDIT_MARKERS = (
    "insufficient credit", "no credit", "credit exhausted", "out of credit",
    "quota exceeded", "quota exhaust", "payment required", "credit not enough",
    "not enough credit", "freecreditsused", "free credits used",
    "free quota", "quota used up", "upgrade your plan", "upgrade to continue",
    "积分不足", "额度不足", "余额不足", "积分用完", "额度用尽", "没有积分", "积分耗尽",
    "额度已用完", "升级套餐",
)
SESSION_DEAD_MARKERS = ("40100", "40101", "token rejected", "refresh token was rejected")


def classify_error(status: int, body: str) -> str:
    """按 HTTP 状态码 + 响应体判定错误类别（判定顺序即优先级，不得重排）。"""
    if status == 402:
        return "hard-credit"
    lower = (body or "").lower()
    for marker in HARD_CREDIT_MARKERS:
        if marker.lower() in lower or marker in (body or ""):
            return "hard-credit"
    for marker in SESSION_DEAD_MARKERS:
        if marker in (body or ""):
            return "session-dead"
    if status == 429:
        return "soft-rate"
    if status == 404:
        return "not-found"
    if status >= 500:
        return "server"
    if status >= 400:
        return "client"
    return "none"


def classify_stream_error(message: str) -> str:
    """流内错误帧（HTTP 200 + SSE ``{error:{message}}``）的类别；未命中关键词按可轮转处理。"""
    by_keyword = classify_error(200, message)
    return "client" if by_keyword == "none" else by_keyword


def error_code_for(kind: str, status: int | None = None) -> str:
    """把已分类的失败映射成本项目的失败码。"""
    if kind == "hard-credit":
        return CODE["quota"]
    if kind == "soft-rate":
        return CODE["quota"]
    if kind == "session-dead":
        return CODE["credential"]
    if status in (401, 403):
        return CODE["credential"]
    if status is not None and 400 <= status < 500:
        return CODE["client"]
    return CODE["server"]


def error_detail(body: str) -> str:
    """从错误体提取可读 detail（对齐 adapter 的 ``errorDetail``）。"""
    try:
        data = json.loads(body)
    except ValueError:
        return body or ""
    if not isinstance(data, dict):
        return body or ""
    parts = []
    if isinstance(data.get("code"), (int, str)):
        parts.append(f"code={data['code']}")
    if isinstance(data.get("message"), str):
        parts.append(data["message"])
    if isinstance(data.get("msg"), str):
        parts.append(data["msg"])
    return " ".join(parts) if parts else (body or "")


# ── 纯函数（lobsterai.ts） ──────────────────────────────────────────────────

def mask_phone_tail(value: str, visible_tail: int = 2) -> str:
    """把手机号（完整或已脱敏）统一掩码为只露末 2 位的形态；非手机号形态原样返回。"""
    import re

    trimmed = (value or "").strip()
    if trimmed == "":
        return trimmed
    if re.fullmatch(r"1\d{10}", trimmed):
        return trimmed[:3] + "*" * (len(trimmed) - 3 - visible_tail) + trimmed[-visible_tail:]
    masked = re.fullmatch(r"(\d{3})(\*+)(\d+)", trimmed)
    if masked:
        total = len(masked.group(1)) + len(masked.group(2)) + len(masked.group(3))
        stars = total - len(masked.group(1)) - visible_tail
        if stars < 0:
            return trimmed
        return masked.group(1) + "*" * stars + masked.group(3)[-visible_tail:]
    return trimmed


def read_string_field(source: Any, key: str) -> str:
    if not isinstance(source, dict):
        return ""
    value = source.get(key)
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def read_number_field(source: Any, key: str) -> float | None:
    if not isinstance(source, dict):
        return None
    value = source.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return float(text)
        except ValueError:
            return None
    return None


def parse_envelope(body: Any) -> dict:
    """解析 ``{code, msg, data}`` 信封；返回 ``{ok, data}`` 或 ``{ok: False, code, message}``。"""
    if not isinstance(body, dict):
        return {"ok": False, "code": -1, "message": "响应不是 JSON 对象"}
    code = read_number_field(body, "code")
    code = -1 if code is None else int(code)
    message = read_string_field(body, "msg") or read_string_field(body, "message")
    if code != 0:
        return {"ok": False, "code": code, "message": message or f"code={code}"}
    data = body.get("data")
    if not isinstance(data, dict):
        return {"ok": False, "code": code, "message": message or "data 为空（accessToken 可能已失效）"}
    return {"ok": True, "data": data}


def jwt_expires_at_ms(token: str) -> int | None:
    """从 JWT payload 读 ``exp``（秒）并换算为毫秒；非 JWT 或解析失败返回 None。"""
    if not isinstance(token, str) or token == "":
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
        return int(exp * 1000)
    return None


def credential_expires_at_ms(credential: dict) -> int | None:
    """兼容毫秒时间戳 / 秒级时间戳 / ISO 8601；为空时回退解析 access_token 的 JWT exp。"""
    from datetime import datetime

    raw = credential.get("expires_at")
    if isinstance(raw, str) and raw != "":
        if raw.isdigit():
            value = int(raw)
            return value if value > 1_000_000_000_000 else value * 1000
        try:
            return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            pass
    return jwt_expires_at_ms(credential.get("access_token") or "")


def is_expired(credential: dict) -> bool:
    expires_at = credential_expires_at_ms(credential)
    return False if expires_at is None else int(time.time() * 1000) >= expires_at


def is_refreshable(credential: dict) -> bool:
    return isinstance(credential.get("refresh_token"), str) and credential["refresh_token"] != ""


def parse_token_payload(data: dict) -> dict:
    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    payload = {
        "accessToken": read_string_field(data, "accessToken"),
        "refreshToken": read_string_field(data, "refreshToken"),
        "userId": read_string_field(user, "id"),
        "yid": read_string_field(user, "yid"),
        "accountUserId": read_string_field(user, "userId"),
        "nickname": read_string_field(user, "nickname"),
    }
    expires_in = read_number_field(data, "expiresIn")
    if expires_in is not None:
        payload["expiresIn"] = expires_in
    return payload


def resolve_uid(payload: dict) -> str:
    """四级回退：``user.id`` → ``user.userId`` → ``user.yid`` → ``sha256(accessToken)[:16]``。"""
    for key in ("userId", "accountUserId", "yid"):
        value = payload.get(key)
        if isinstance(value, str) and value != "":
            return value
    digest = hashlib.sha256((payload.get("accessToken") or "").encode("utf-8")).hexdigest()
    return digest[:16]


def build_credential(payload: dict, session: dict) -> dict:
    """由令牌载荷组装可持久化凭据；``expiresIn`` 以当前时刻为基准。"""
    expires_in = payload.get("expiresIn")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        expires_at = str(int(time.time() * 1000) + int(expires_in) * 1000)
    else:
        exp = jwt_expires_at_ms(payload.get("accessToken") or "")
        expires_at = "" if exp is None else str(exp)
    account_user_id = payload.get("accountUserId") or ""
    return {
        "access_token": payload.get("accessToken") or "",
        "refresh_token": payload.get("refreshToken") or "",
        "expires_at": expires_at,
        "uid": resolve_uid(payload),
        "user_id": account_user_id if account_user_id != "" else (payload.get("yid") or ""),
        "nickname": payload.get("nickname") or "",
        "uuid": session.get("uuid", ""),
        "first_keyfrom": session.get("firstKeyfrom", ""),
        "latest_keyfrom": session.get("latestKeyfrom", ""),
    }


def apply_refresh(previous: dict, payload: dict, now_ms: int | None = None) -> dict:
    """用续期结果更新凭据；``latest_keyfrom`` 等身份字段一律沿用旧值（对齐 Go）。"""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    expires_in = payload.get("expiresIn")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        expires_at = str(now_ms + int(expires_in) * 1000)
    else:
        exp = jwt_expires_at_ms(payload.get("accessToken") or "")
        expires_at = previous.get("expires_at", "") if exp is None else str(exp)
    out = dict(previous)
    out["access_token"] = payload.get("accessToken") or ""
    if payload.get("refreshToken"):
        out["refresh_token"] = payload["refreshToken"]
    out["expires_at"] = expires_at
    return out


def keyfrom_body(credential: dict, client_version: str) -> dict:
    """构造 exchange / refresh / models 共用的身份载荷。"""
    body: dict[str, Any] = {
        "firstKeyfrom": credential.get("first_keyfrom") or "",
        "latestKeyfrom": credential.get("latest_keyfrom") or "",
        "version": client_version,
    }
    if credential.get("uuid"):
        body["uuid"] = credential["uuid"]
    if credential.get("user_id"):
        body["userId"] = credential["user_id"]
    return body


def refresh_body(credential: dict, client_version: str) -> dict:
    body = keyfrom_body(credential, client_version)
    body["refreshToken"] = credential.get("refresh_token") or ""
    return body


def anonymous_headers() -> dict[str, str]:
    """exchange / refresh 用：**不带 Authorization**。"""
    return {"Accept": "application/json", "Content-Type": "application/json", "User-Agent": USER_AGENT}


def auth_headers(credential: dict, accept: str = "application/json") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {credential.get('access_token') or ''}",
        "Accept": accept,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }


def chat_headers(credential: dict, client_version: str) -> dict[str, str]:
    headers = auth_headers(credential, "text/event-stream, application/json")
    headers["X-LobsterAI-Client-Capabilities"] = CLIENT_CAPABILITIES
    headers["X-LobsterAI-Client-Version"] = client_version
    return headers


def models_headers(credential: dict, client_version: str) -> dict[str, str]:
    headers = auth_headers(credential, "application/json")
    headers["X-LobsterAI-Client-Capabilities"] = CLIENT_CAPABILITIES
    headers["X-LobsterAI-Client-Version"] = client_version
    return headers


def parse_client_version(raw: Any) -> str | None:
    import re

    if not isinstance(raw, str):
        return None
    trimmed = raw.strip()
    return trimmed if re.fullmatch(r"(\d+(?:\.\d+)*)(?:-[0-9A-Za-z.-]+)?", trimmed) else None


def parse_client_version_from_update(body: Any) -> str | None:
    outer = body.get("data") if isinstance(body, dict) else None
    value = outer.get("value") if isinstance(outer, dict) else None
    return parse_client_version(value.get("version") if isinstance(value, dict) else None)


class ClientVersionResolver:
    """客户端版本号解析器：进程内缓存（12h）→ 远端更新接口 → 兜底常量。"""

    def __init__(self, ttl_s: float = VERSION_CACHE_TTL_S) -> None:
        self._cached: str | None = None
        self._cached_at = 0.0
        self._ttl = ttl_s
        self._lock = asyncio.Lock()

    async def resolve(self) -> str:
        now = time.time()
        if self._cached is not None and now - self._cached_at < self._ttl:
            return self._cached
        async with self._lock:
            now = time.time()
            if self._cached is not None and now - self._cached_at < self._ttl:
                return self._cached
            client = await get_client()
            try:
                response = await client.get(CLIENT_VERSION_API,
                                            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                                            timeout=REQUEST_TIMEOUT_S)
                if response.status_code < 400:
                    version = parse_client_version_from_update(response.json())
                    if version is not None:
                        self._cached = version
                        self._cached_at = time.time()
                        return version
            except Exception:  # noqa: BLE001
                pass
            # 失败不回退缓存：一次瞬时故障不该在 TTL 内持续影响后续请求。
            return FALLBACK_CLIENT_VERSION


CLIENT_VERSION = ClientVersionResolver()


def read_model_array(body: Any) -> list:
    """兼容单层（``data`` 直接是数组）与双层（``data.data``）两种形状。"""
    if not isinstance(body, dict):
        return []
    code = read_number_field(body, "code")
    if code is None or int(code) != 0:
        return []
    data = body.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return data["data"]
    return []


def parse_models(body: Any) -> list[dict]:
    """解析 ``GET /api/models/available``；可选字段缺失一律留空（绝不编造值）。"""
    options = {"off", "minimal", "low", "medium", "high", "xhigh", "max"}

    def parse_thinking_config(value: Any) -> dict | None:
        if not isinstance(value, dict):
            return None
        raw_options = value.get("options")
        if not isinstance(raw_options, list) or not raw_options:
            return None
        parsed: list[dict] = []
        levels: set[str] = set()
        wire_levels: set[str] = set()
        for raw in raw_options:
            if not isinstance(raw, dict):
                return None
            level = raw.get("level") if isinstance(raw.get("level"), str) else ""
            wire = raw.get("openclawLevel") if isinstance(raw.get("openclawLevel"), str) else ""
            if level not in options or wire not in (options - {"max"}):
                return None
            if level in levels or wire in wire_levels:
                return None
            if (level == "off") != (wire == "off"):
                return None
            levels.add(level)
            wire_levels.add(wire)
            parsed.append({"level": level, "openclawLevel": wire})
        if len(parsed) == 1 and parsed[0]["level"] == "off":
            return None
        default_level = value.get("defaultLevel") if isinstance(value.get("defaultLevel"), str) else ""
        if default_level not in levels:
            return None
        return {"options": parsed, "defaultLevel": default_level}

    models: list[dict] = []
    for item in read_model_array(body):
        if not isinstance(item, dict):
            continue
        model_id = read_string_field(item, "modelId")
        if model_id == "":
            continue
        name = read_string_field(item, "modelName")
        model: dict[str, Any] = {"id": model_id, "name": name if name != "" else model_id}
        context_window = read_number_field(item, "contextWindow")
        if context_window is not None and context_window > 0:
            model["contextWindow"] = int(context_window)
        max_tokens = read_number_field(item, "maxTokens")
        if max_tokens is not None and max_tokens > 0:
            model["maxOutput"] = int(max_tokens)
        if isinstance(item.get("supportsImage"), bool):
            model["vision"] = item["supportsImage"]
        if isinstance(item.get("supportsThinking"), bool):
            model["reasoning"] = item["supportsThinking"]
        thinking = parse_thinking_config(item.get("thinkingConfig"))
        if thinking is not None:
            model["thinkingConfig"] = thinking
        capabilities = item.get("requestCapabilities")
        if isinstance(capabilities, list):
            kept = [c for c in capabilities if isinstance(c, str)]
            if kept:
                model["requestCapabilities"] = kept
        description = read_string_field(item, "description")
        if description != "":
            model["description"] = description
        cost_multiplier = read_number_field(item, "costMultiplier")
        if cost_multiplier is not None and cost_multiplier > 0:
            # 倍率写进 name（模型切换菜单只渲染 name）。
            model["costMultiplier"] = cost_multiplier
            model["name"] = f"{model['name']} · x{cost_multiplier}"
        models.append(model)
    return models


def build_models_query(credential: dict, client_version: str) -> str:
    """模型列表 query（keyfrom 身份载荷，**不含 refreshToken**）。"""
    from urllib.parse import urlencode

    body = keyfrom_body(credential, client_version)
    return urlencode({k: v for k, v in body.items() if isinstance(v, str) and v != ""})


def display_nickname(credential: dict, fallback_id: str) -> str:
    nickname = (credential.get("nickname") or "").strip() if isinstance(credential.get("nickname"), str) else ""
    return fallback_id if nickname == "" else mask_phone_tail(nickname)


# ── 网络：版本 / 模型目录 / 续期 ────────────────────────────────────────────

async def _exchange(code: str, session: dict, client_version: str) -> dict:
    body = {
        "authCode": code,
        "firstKeyfrom": session["firstKeyfrom"],
        "latestKeyfrom": str(int(time.time() * 1000)),
        "uuid": session["uuid"],
        "version": client_version,
    }
    client = await get_client()
    try:
        response = await client.post(f"{API_BASE}{EXCHANGE_PATH}", headers=anonymous_headers(),
                                     content=json.dumps(body), timeout=REQUEST_TIMEOUT_S)
    except httpx.HTTPError as error:
        raise UpstreamError(f"LobsterAI exchange 网络失败：{error}", CODE["transport"])
    try:
        parsed = response.json()
    except ValueError:
        raise UpstreamError(f"LobsterAI exchange 响应不是 JSON（HTTP {response.status_code}）", CODE["server"],
                            status=response.status_code)
    envelope = parse_envelope(parsed)
    if not envelope["ok"]:
        raise UpstreamError(f"LobsterAI exchange 失败：{envelope['message']}", CODE["credential"],
                            status=response.status_code)
    payload = parse_token_payload(envelope["data"])
    if payload["accessToken"] == "":
        raise UpstreamError("LobsterAI exchange 响应缺少 accessToken", CODE["credential"],
                            status=response.status_code)
    return build_credential(payload, {"uuid": session["uuid"], "firstKeyfrom": session["firstKeyfrom"],
                                      "latestKeyfrom": body["latestKeyfrom"]})


async def refresh_credential(credential: dict) -> dict:
    """静默续期：``refreshToken`` + keyfrom 身份载荷换取新令牌（不带 Authorization）。"""
    if not is_refreshable(credential):
        raise UpstreamError("LobsterAI 无 refresh_token，请重新登录", CODE["credential"])
    client_version = await CLIENT_VERSION.resolve()
    body = refresh_body(credential, client_version)
    client = await get_client()
    try:
        response = await client.post(f"{API_BASE}{REFRESH_PATH}", headers=anonymous_headers(),
                                     content=json.dumps(body), timeout=REQUEST_TIMEOUT_S)
    except httpx.HTTPError as error:
        raise UpstreamError(f"LobsterAI 续期网络失败：{error}", CODE["transport"])
    try:
        parsed = response.json()
    except ValueError:
        raise UpstreamError(f"LobsterAI 续期响应不是 JSON（HTTP {response.status_code}）", CODE["server"],
                            status=response.status_code)
    envelope = parse_envelope(parsed)
    if not envelope["ok"]:
        kind = classify_error(response.status_code, json.dumps(parsed, ensure_ascii=False))
        code = CODE["credential"] if response.status_code in (401, 403) or kind == "session-dead" else CODE["server"]
        raise UpstreamError(f"LobsterAI 续期失败：{envelope['message']}", code, status=response.status_code)
    payload = parse_token_payload(envelope["data"])
    if payload["accessToken"] == "":
        raise UpstreamError("续期响应缺少 accessToken，请重新登录", CODE["credential"],
                            status=response.status_code)
    return apply_refresh(credential, payload)


async def fetch_models(credential: dict) -> dict:
    """``GET /api/models/available``；失败一律回退内置兜底表，不抛错。"""
    try:
        client_version = await CLIENT_VERSION.resolve()
        query = build_models_query(credential, client_version)
        url = f"{API_BASE}{MODELS_PATH}" + (f"?{query}" if query else "")
        client = await get_client()
        response = await client.get(url, headers=models_headers(credential, client_version),
                                    timeout=REQUEST_TIMEOUT_S)
        if response.status_code >= 400:
            raise UpstreamError(f"lobsterai model listing failed: HTTP {response.status_code}", CODE["server"],
                                status=response.status_code)
        models = parse_models(response.json())
        if models:
            return {"models": models, "at": int(time.time() * 1000)}
    except Exception:  # noqa: BLE001
        pass
    return {"models": [dict(model, contextWindow=CONTEXT_WINDOWS.get(model["id"], 131_072))
                       for model in FALLBACK_MODELS], "fallback": True}


# ── 登录（lobsterai-oauth.ts） ──────────────────────────────────────────────

def build_login_url(port: int, state: str) -> str:
    from urllib.parse import urlencode

    redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"
    query = urlencode({"source": "electron", "redirect_uri": redirect_uri, "state": state})
    return f"{PORTAL_BASE}/portal#/login?{query}"


def _open_external(url: str) -> bool:
    try:
        import subprocess
        import sys

        if sys.platform == "win32":
            subprocess.Popen(["cmd", "/c", "start", "", url], shell=False)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["xdg-open", url])
        return True
    except Exception:  # noqa: BLE001
        return False


async def run_login(*, open_browser: bool = True, timeout_s: int = LOGIN_TIMEOUT_S) -> dict:
    """完整登录：起本地回调服务器 → 打开 portal → 收 ``code`` → 本进程内完成 exchange。"""
    session = {"uuid": str(uuid.uuid4()), "firstKeyfrom": str(int(time.time() * 1000))}
    state = str(uuid.uuid4())
    done = asyncio.Event()
    captured: dict[str, str] = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            from urllib.parse import parse_qs, urlsplit

            target = (request_line.split(" ") + ["", "", ""])[1]
            parsed = urlsplit(target)
            query = parse_qs(parsed.query)
            code = (query.get("code") or [""])[0]
            got_state = (query.get("state") or [""])[0]
            if not parsed.path.startswith(CALLBACK_PATH):
                body, status = "Not found", "404 Not Found"
            elif code == "" or got_state != state:
                body, status = "登录回调参数无效", "400 Bad Request"
            else:
                captured["code"] = code
                body, status = "<html><body><h2>登录成功，可以关闭此窗口了</h2></body></html>", "200 OK"
            payload = body.encode("utf-8")
            writer.write(f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
                         f"Content-Length: {len(payload)}\r\n\r\n".encode("latin-1") + payload)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            with __import__("contextlib").suppress(Exception):
                writer.close()
            done.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    login_url = build_login_url(port, state)
    if open_browser:
        _open_external(login_url)
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        raise UpstreamError(f"LobsterAI 登录超时（{timeout_s} 秒内未完成）", CODE["timeout"])
    finally:
        server.close()
        with __import__("contextlib").suppress(Exception):
            await server.wait_closed()

    code = captured.get("code")
    if not code:
        raise UpstreamError("LobsterAI 登录回调参数无效（缺少 code 或 state 不匹配）", CODE["credential"])
    client_version = await CLIENT_VERSION.resolve()
    credential = await _exchange(code, session, client_version)
    credential["loginUrl"] = login_url
    credential["nickname"] = display_nickname(credential, credential.get("uid") or "lobsterai")
    return credential


# ── 推理（lobsterai-adapter.ts） ────────────────────────────────────────────

def _build_payload(body: dict) -> dict:
    """按 TS 适配器构造的上游请求体（**不含** ``prompt_cache_key`` / 腾讯系归属头）。"""
    payload: dict[str, Any] = {
        "model": body.get("model") or "",
        "messages": body.get("messages") or [],
        # 上游只支持 SSE，stream 恒为 true。
        "stream": True,
    }
    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        payload["tools"] = tools
    temperature = body.get("temperature")
    if isinstance(temperature, (int, float)) and not isinstance(temperature, bool):
        payload["temperature"] = temperature
    max_tokens = body.get("max_tokens")
    if isinstance(max_tokens, int) and not isinstance(max_tokens, bool) and max_tokens > 0:
        payload["max_tokens"] = max_tokens
    stop = body.get("stop")
    if isinstance(stop, list) and stop:
        payload["stop"] = stop
    effort = body.get("reasoning_effort")
    if effort is not None:
        payload["reasoning_effort"] = effort
    return payload


def _usage_chunk(raw: Any) -> dict:
    """把 ``read_stream`` 汇总的 usage 投影成内部 ``usage`` chunk。

    字段名照抄本项目约定（``inputTokens`` 只含未缓存输入，缓存命中单列
    ``cacheReadTokens``），``reasoningTokens`` 恒存在（缺省 0）——
    与 adapter 收尾发 usage 的口径一致。
    """
    usage = raw if isinstance(raw, dict) else {}

    def number(key: str) -> int:
        value = usage.get(key)
        return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

    out = {
        "inputTokens": number("inputTokens"),
        "outputTokens": number("outputTokens"),
        "totalTokens": number("totalTokens"),
        "reasoningTokens": number("reasoningTokens"),
    }
    if number("cacheReadTokens") > 0:
        out["cacheReadTokens"] = number("cacheReadTokens")
    return out


def _finish_of(state: dict, blocks: int) -> dict:
    """由 ``read_stream`` 的汇总状态算出 ``finish`` 的 reason。

    映射完全对齐 TS 适配器收尾的那段判定：

    - 工具参数残缺（``brokenToolCall``）→ ``max-tokens``（报 ``tool-calls``
      会让 harness 执行半截 JSON 参数，模型随后陷入重试循环）；
    - 有工具调用却没收到 ``finish_reason`` → ``max-tokens``（连接被掐断）；
    - 其余按上游 ``finish_reason`` 走 ``finish_reason()`` 的既有映射
      （``length`` / ``max_tokens`` → ``max-tokens``，``tool_calls`` → ``tool-calls``）；
    - 零块 + ``stop`` → 改报 ``error``（``EMPTY_RESPONSE``），
      与 ``resolveEmptyResponseReason`` 同义：不许静默结束。
    """
    if state.get("brokenToolCall") is True:
        kind = "max-tokens"
    elif state.get("sawToolCall") is True and state.get("sawFinish") is not True:
        kind = "max-tokens"
    else:
        kind = finish_reason(state.get("finish") if isinstance(state.get("finish"), str) else None)["kind"]
    if kind == "stop" and blocks == 0:
        return {"kind": "error",
                "failure": {"message": "model returned a completed response with no content",
                            "code": CODE["empty"]}}
    return {"kind": kind}


def _feed_frame(channel, text: str) -> None:
    """SSE ``data:`` 负载 → 通道。

    上游把业务失败（典型：额度耗尽）放进**流内错误帧**
    （HTTP 200 + ``{"error":{"message":"免费额度已用完，请升级套餐"}}``），
    故这里先按 ``classify_stream_error`` 分类再抛，错误码与 TS 的
    ``LobsteraiStreamError`` 同源（``hard-credit`` → 额度码，其余 → 服务端码）。
    """
    try:
        payload = json.loads(text)
    except ValueError:
        channel.push(text)
        return
    if isinstance(payload, dict) and (payload.get("error") or payload.get("type") == "error"):
        frame = payload.get("error") if isinstance(payload.get("error"), dict) else payload
        detail = frame.get("message") if isinstance(frame.get("message"), str) else "unknown error"
        kind = classify_stream_error(detail)
        raise UpstreamError(f"lobsterai: {detail}", error_code_for(kind), kind=kind, detail=detail)
    channel.push(json.dumps(payload, ensure_ascii=False))


async def _send_chat(client: httpx.AsyncClient, client_version: str, credential: dict, data: bytes, url: str):
    """发一次 chat 请求；网络失败映射为可重试的 TRANSPORT 失败。

    请求头按 ``chat_headers``（Bearer + ``X-LobsterAI-Client-*``），
    请求体 ``stream`` 恒为 ``true``（上游只支持 SSE）。
    """
    try:
        return await client.send(client.build_request("POST", url, headers=chat_headers(credential, client_version),
                                                      content=data), stream=True)
    except httpx.HTTPError as error:
        raise UpstreamError(f"lobsterai: transport error: {error}", CODE["transport"])


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """POST 一轮 chat/completions 并以内部 chunk 产出。

    SSE 的逐帧解析与块组装交给 ``read_stream``（``wire="chat"``）：
    ``reasoning_content`` 走 ``reasoning-delta``，``tool_calls`` 按 ``index``
    合并后走 ``tool-call-delta``，收尾由本函数补 ``usage`` 与 ``finish``。
    ``catalog`` 本渠道不使用（每轮直发 ``model``，无额度路由），保留形参以对齐渠道约定。
    """
    client_version = await CLIENT_VERSION.resolve()
    payload = _build_payload(body)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    url = f"{API_BASE}{CHAT_PATH}"
    channel = create_channel()
    client = await get_client()

    async def produce() -> None:
        nonlocal credential
        response = None
        try:
            response = await _send_chat(client, client_version, credential, data, url)
            # 401/403：静默续期一次后原样重发（对齐 TS：不区分具体原因，先刷新再试）。
            if response.status_code in (401, 403):
                await response.aread()
                await response.aclose()
                refreshed = await refresh_credential(credential)
                credential = refreshed
                if on_refresh is not None:
                    on_refresh(refreshed)
                response = await _send_chat(client, client_version, credential, data, url)
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                detail = error_detail(text)
                kind = classify_error(response.status_code, text)
                raise UpstreamError(f"lobsterai: {detail}", error_code_for(kind, response.status_code),
                                    status=response.status_code, kind=kind, detail=detail)
            head = await read_head(response.aiter_bytes(), 4096, STREAM_TIMEOUT_S)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("lobsterai: empty model response body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), lambda text: _feed_frame(channel, text), STREAM_TIMEOUT_S)
            else:
                text = (await _read_remainder(head)).decode("utf-8", "replace")
                try:
                    parsed = json.loads(text)
                except ValueError:
                    raise UpstreamError("lobsterai: unexpected non-stream response", CODE["server"])
                _feed_frame(channel, json.dumps(parsed, ensure_ascii=False))
            channel.push(None)
        except BaseException as error:  # noqa: BLE001
            channel.push(error if isinstance(error, BaseException) else RuntimeError(str(error)))
        finally:
            if response is not None:
                try:
                    await response.aclose()
                except Exception:  # noqa: BLE001
                    pass

    task = asyncio.create_task(produce())
    reader = read_stream(channel.read(), "chat", None, None)
    blocks = 0
    try:
        while True:
            done, value = await reader.next()
            if done:
                state = value if isinstance(value, dict) else {}
                yield {"type": "usage", "usage": _usage_chunk(state.get("usage"))}
                yield {"type": "finish", "reason": _finish_of(state, blocks)}
                return
            if isinstance(value, dict) and value.get("type") == "block-end":
                blocks += 1
            yield value
    finally:
        await reader.close()
        if not task.done():
            task.cancel()
        try:
            await task
        except BaseException:  # noqa: BLE001
            pass
