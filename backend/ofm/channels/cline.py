"""Cline（Cline / cline.bot，WorkOS 设备码轮询登录）渠道。

移植自原版 channel-pack 的 ``cline.ts``（凭据与协议纯函数）、``cline-product.ts``
（产品配置与端点常量）、``cline-oauth.ts``（登录）、``cline-auth.ts``（续期）、
``cline-adapter.ts``（推理请求构造）与 ``cline-models.ts``（模型目录）。
SSE 的逐帧解析与块组装走 ``..stream.read_stream``（语义等价原版 ``sse.ts`` 的
``consumeOpenAiSse``），故本模块只负责「端点 + 鉴权头 + 请求体 + 登录 + 目录」。

## 与既有渠道的差异（全部踩过或差点踩）

1. **访问令牌带 ``workos:`` 前缀且不可剥**（``clineBearerValue``）：官方磁盘上存的
   就是 ``workos:eyJ…``，前缀只在**解码 JWT** 时被剥掉，**从不出现在请求头构造里**。
   实测：``Bearer workos:eyJ…`` → 200；剥成 ``Bearer eyJ…`` → 401（文案还是
   "make sure you're using the latest version of Cline"，与真实原因毫不相干）。
2. **思考字段是 ``delta.reasoning``**（不是 ``reasoning_content``）：只认后者会让
   Cline 的思考内容被静默丢弃（表现为「模型不思考」、档位切换看似无效）。
3. **续期请求体是驼峰 ``{refreshToken, grantType}``**，不是 OAuth 标准的
   ``refresh_token`` / ``grant_type``。
4. **注册/续期响应套一层 ``{success, data}`` 信封**，字段名是驼峰 ``accessToken``；
   判据是 ``success && data.accessToken``，只看裸字段会把失败信封当成成功。
5. **免费模型只由 ``recommended-models`` 下发**：``/api/v1/models`` 的 460 个 id 里
   根本没有 ``cline-free/*``（免费模型是独立 id，与按量计费的 ``deepseek/…``
   是两个条目，绝不可做「名字包含 deepseek」之类的模糊匹配）。
6. **403 必须先排除「地域限制」**：``{"error":"access forbidden: … is not available
   in your region"}``。它只与响应体文案有关，续期在这里永远无用。

登录三步协议（全部来自 `cline-oauth.ts` 的实测记录）：

```
1) POST {workOsBase}/user_management/authorize/device
     Content-Type: application/x-www-form-urlencoded
     body: client_id=<workOsClientId>
   → { device_code, user_code, verification_uri, verification_uri_complete,
       expires_in, interval }
2) 轮询 POST {workOsBase}/user_management/authenticate
     body: grant_type=urn:ietf:params:oauth:grant-type:device_code
           &device_code=<device_code>&client_id=<workOsClientId>
   → 200 { access_token, refresh_token, token_type }
   → 错误体 { error: "authorization_pending" | "slow_down" | … }
3) POST {apiBase}/api/v1/auth/register
     body: { accessToken, refreshToken }
   → { success: true, data: { accessToken, refreshToken, expiresAt,
                              tokenType, userInfo: { clineUserId, email, … } } }
```

⚠️ ``authorization_pending`` **不是错误**，必须继续轮询；``slow_down`` 必须真的
**累积**退避（源码 ``intervalSeconds += 1``），否则会被 WorkOS 持续限流。
设备码流程**不起本地端口**，也就没有端口占用与回调伪造问题。
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import finish_reason, read_stream

CHANNEL_ID = "cline"

# ── 端点与常量（cline-product.ts 的 CLINE 与端点路径常量） ──────────────────

API_BASE = "https://api.cline.bot"
APP_BASE = "https://app.cline.bot"
WORKOS_BASE = "https://api.workos.com"
#: WorkOS client id（``CLINE_ENVIRONMENTS.production.workOsClientId``）；
#: 与凭据 JWT 的 ``client_id`` claim 一致（实测）。本模块只支持 prod。
WORKOS_CLIENT_ID = "client_01K3A541FN8TA3EPPHTD2325AR"
#: 访问令牌前缀；**不可剥**（见模块头第 1 条）。
TOKEN_PREFIX = "workos:"

#: 官方客户端标识头（``DEFAULT_CLINE_REQUEST_HEADERS``）。推理、账号与目录端点都要带。
CLIENT_HEADERS: dict[str, str] = {
    "HTTP-Referer": "https://cline.bot",
    "X-Title": "Cline",
    "X-IS-MULTIROOT": "false",
    "X-CLIENT-TYPE": "cline-sdk",
}

DEVICE_AUTHORIZATION_PATH = "/user_management/authorize/device"
DEVICE_AUTHENTICATE_PATH = "/user_management/authenticate"
REGISTER_PATH = "/api/v1/auth/register"
REFRESH_PATH = "/api/v1/auth/refresh"
CHAT_PATH = "/api/v1/chat/completions"
MODELS_PATH = "/api/v1/models"
RECOMMENDED_MODELS_PATH = "/api/v1/ai/cline/recommended-models"
ME_PATH = "/api/v1/users/me"

#: 单次控制面请求超时（对齐源码 ``DEFAULT_HTTP_TIMEOUT_MS``）。
CLINE_HTTP_TIMEOUT_S = 30.0
#: 设备码默认有效期 / 轮询间隔（``DEFAULT_DEVICE_AUTH_*``）。
DEVICE_AUTH_EXPIRES_MS = 300_000
DEVICE_AUTH_INTERVAL_MS = 5_000
#: 连续网络失败多少次后放弃轮询。
POLL_MAX_FAILURES = 5
#: 模型目录请求超时（``CLINE_MODELS_TIMEOUT_MS``）。
MODELS_TIMEOUT_S = 20.0
#: 推理流超时。
STREAM_TIMEOUT_S = 600.0
#: 单次输出上限的安全边界：内嵌目录里最大的 ``maxTokens`` 是 943718
#: （``muse-spark-1.3-contributor``），不自行编造更大的值。
MAX_OUTPUT_TOKENS = 943_718

#: 设备码轮询的服务端 grant_type。
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

# ── 免费判定与展示（cline-models.ts） ──────────────────────────────────────

#: 免费 id 的**后缀**约定（用后缀而非 ``:free in id``：``foo:freebar`` 不该命中）。
FREE_ID_SUFFIX = ":free"
#: 免费 id 的**前缀**约定（``cline-free/`` 命名空间）。
FREE_ID_PREFIX = "cline-free/"

#: 全 provider 统一的思考档位（产品决策：远端不下发档位）。
#: ``id`` 是 wire 值，``name`` 是展示名 —— 最高档 wire 是 ``max`` 而 UI 显示 Extra。
CLINE_REASONING_EFFORTS: list[dict] = [
    {"id": "none", "name": "None"},
    {"id": "low", "name": "Low"},
    {"id": "medium", "name": "Medium"},
    {"id": "high", "name": "High"},
    {"id": "max", "name": "Extra"},
]
#: 默认档位。实测不传 ``reasoning_effort`` 时模型**完全不思考**。
CLINE_DEFAULT_REASONING_EFFORT = "high"

#: 兜底模型目录（``cline-product.ts`` 的 ``CLINE_FALLBACK_MODELS``，2026-10-05 快照）。
#: 它是**编译期快照**：上游撤掉某个免费模型时不会跟着变，故只在远端不可用时整表兜底。
FALLBACK_MODELS: list[dict] = [
    {
        "id": "stealth/space-bunny-alpha",
        "name": "Space Bunny Alpha",
        "contextWindow": 1_000_000,
        "maxTokens": 524_288,
        "supportsImage": True,
        "isFree": True,
        "description": "Blazing-fast inference with 1M context",
    },
    {
        "id": "cline-free/mimo-v2.6-flash",
        "name": "MiMo-V2.6-Flash",
        "contextWindow": 1_048_576,
        "maxTokens": 131_072,
        "supportsImage": True,
        "isFree": True,
        "description": "Mixture-of-Experts architecture with 309B total parameters",
    },
    {
        "id": "cline-free/muse-spark-1.3-contributor",
        "name": "Muse Spark 1.3 Contributor",
        "contextWindow": 1_048_576,
        "maxTokens": 943_718,
        "supportsImage": True,
        "isFree": True,
        "description": (
            "Meta\u2019s multimodal reasoning model for experimentation, learning, "
            "and early-stage agentic, multi-agent, and coding workflows."
        ),
    },
]

FALLBACK_INDEX: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS}
#: 管理器在远端未下发 ``contextWindow`` 时按此表回填（``manager._context_for``）。
CONTEXT_WINDOWS: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS}

_WORD_START = re.compile(r"\b\w")


def is_free_model(model_id: str, remote_free_ids: set[str], fallback: dict | None = None) -> bool:
    """免费判定：远端 ``free`` 集合 ∪ ``:free`` 后缀 ∪ ``cline-free/`` 前缀 ∪ 兜底表。"""
    if model_id in remote_free_ids:
        return True
    if model_id.endswith(FREE_ID_SUFFIX):
        return True
    if model_id.startswith(FREE_ID_PREFIX):
        return True
    return (fallback or {}).get("isFree") is True


def display_name(model_id: str) -> str:
    """由 id 派生可读名（去掉命名空间前缀，只求可读）。"""
    slash = model_id.find("/")
    tail = model_id[slash + 1:] if slash >= 0 else model_id
    return _WORD_START.sub(lambda match: match.group(0).upper(), tail.replace(FREE_ID_SUFFIX, "").replace("-", " "))


def with_free_mark(name: str, is_free: bool) -> str:
    """免费模型在 **name** 里拼 `` · 免费``（选择列表只渲染 name，不读 description）。"""
    return f"{name} · 免费" if is_free else name


# ── 凭据模型（cline.ts） ────────────────────────────────────────────────────


def read_string(source: Any, keys: tuple[str, ...]) -> str | None:
    """读第一个非空字符串字段（对齐 ``readString``：trim 后为空视为缺失）。"""
    if not isinstance(source, dict):
        return None
    for key in keys:
        value = source.get(key)
        if isinstance(value, str) and value.strip() != "":
            return value.strip()
    return None


def parse_timestamp(value: Any) -> int | None:
    """把各种时间形态归一为**毫秒**时间戳（对齐 ``parseClineTimestamp``）。

    Cline 实测下发 ISO 8601 字符串（源码直接 ``Date.parse``）；数字形态按
    10 位=秒 / 13 位=毫秒兼容，以对上游格式变更鲁棒。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value) and value > 0:
        return int(round(value * 1000)) if value < 1e12 else int(round(value))
    if isinstance(value, str) and value.strip() != "":
        text = value.strip()
        if text.isdigit():
            number = int(text)
            return number * 1000 if number < 1_000_000_000_000 else number
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    return None


def parse_token_payload(value: Any) -> dict:
    """解析注册 / 续期响应（``parseClineTokenPayload``）。

    两处响应**同构**：``{success, data: {accessToken, refreshToken, expiresAt,
    tokenType, userInfo: {clineUserId, email, firstName, lastName}}}``。
    兼容无 ``data`` 信封的裸响应。垃圾输入返回空 ``accessToken``（不抛错）。
    """
    if not isinstance(value, dict):
        return {"accessToken": ""}
    envelope: dict = value
    inner: dict = envelope["data"] if isinstance(envelope.get("data"), dict) else envelope

    access_token = read_string(inner, ("accessToken", "access_token")) or ""
    payload: dict = {"accessToken": access_token}
    refresh_token = read_string(inner, ("refreshToken", "refresh_token"))
    if refresh_token is not None:
        payload["refreshToken"] = refresh_token
    expires_at = parse_timestamp(inner.get("expiresAt", inner.get("expires_at", inner.get("expire_time"))))
    if expires_at is not None:
        payload["expiresAt"] = expires_at

    user_info = inner.get("userInfo") if isinstance(inner.get("userInfo"), dict) else None
    if user_info is None:
        account_id = read_string(inner, ("accountId", "account_id"))
        email = read_string(inner, ("email",))
        display = None
    else:
        account_id = read_string(user_info, ("clineUserId", "accountId")) or read_string(inner, ("accountId", "account_id"))
        email = read_string(user_info, ("email",)) or read_string(inner, ("email",))
        first = read_string(user_info, ("firstName",))
        last = read_string(user_info, ("lastName",))
        display = " ".join(part for part in (first, last) if part is not None).strip()
    if account_id is not None:
        payload["accountId"] = account_id
    if email is not None:
        payload["email"] = email
    if isinstance(display, str) and display != "":
        payload["displayName"] = display
    return payload


def bearer_value(access_token: Any) -> str:
    """幂等补齐产品前缀（``clineBearerValue``）：空串返回空串，已有前缀原样返回。"""
    token = access_token.strip() if isinstance(access_token, str) else ""
    if token == "":
        return ""
    return token if token.startswith(TOKEN_PREFIX) else f"{TOKEN_PREFIX}{token}"


def build_credential(payload: dict, fallback: dict | None = None) -> dict:
    """构造持久化凭据（``buildClineCredential``）。昵称优先邮箱，其次显示名，最后账号 id。"""
    fallback = fallback if isinstance(fallback, dict) else {}
    account_id = payload.get("accountId") or fallback.get("accountId")
    email = payload.get("email") or fallback.get("email")
    nickname = email or payload.get("displayName") or account_id
    credential: dict = {"access_token": bearer_value(payload.get("accessToken"))}
    if payload.get("refreshToken") is not None:
        credential["refresh_token"] = payload["refreshToken"]
    if payload.get("expiresAt") is not None:
        credential["expire_time"] = payload["expiresAt"]
    if account_id is not None:
        credential["account_id"] = account_id
    if email is not None:
        credential["email"] = email
    if nickname is not None:
        credential["nickname"] = nickname
    return credential


def apply_refresh(credential: dict, payload: dict) -> dict:
    """把一次续期结果合并回既有凭据（``applyClineRefresh``）。

    **保留** ``account_id`` / ``email`` / ``nickname``：它们不在续期响应里，
    丢了会让账号卡片失去展示名。
    """
    next_credential = dict(credential)
    next_credential["access_token"] = bearer_value(payload.get("accessToken"))
    if payload.get("refreshToken") is not None:
        next_credential["refresh_token"] = payload["refreshToken"]
    if payload.get("expiresAt") is not None:
        next_credential["expire_time"] = payload["expiresAt"]
    if payload.get("accountId") is not None:
        next_credential["account_id"] = payload["accountId"]
    if payload.get("email") is not None:
        next_credential["email"] = payload["email"]
    return next_credential


def cline_refresh_body(credential: dict) -> dict:
    """续期请求体：驼峰 ``refreshToken`` + ``grantType``（两者都是必填）。"""
    refresh = credential.get("refresh_token") if isinstance(credential, dict) else None
    return {"refreshToken": refresh if isinstance(refresh, str) else "", "grantType": "refresh_token"}


def credential_expires_at_ms(credential: dict) -> int | None:
    value = credential.get("expire_time") if isinstance(credential, dict) else None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return int(value)
    return None


def is_refreshable(credential: dict) -> bool:
    if not isinstance(credential, dict):
        return False
    token = credential.get("refresh_token")
    return isinstance(token, str) and token != ""


def is_expired(credential: dict, now_ms: int | None = None) -> bool:
    """访问令牌是否已过期；无过期时间时保守视为未过期（交给服务端 401 判定）。"""
    expires_at = credential_expires_at_ms(credential)
    if expires_at is None:
        return False
    return expires_at <= (now_ms if now_ms is not None else int(time.time() * 1000))


# ── 请求头（cline.ts 的 clineHeaders / clineAuthHeaders） ───────────────────


def auth_headers(access_token: Any, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Bearer 值是**带 ``workos:`` 前缀**的令牌，且必须叠加官方客户端的标识头。"""
    headers: dict[str, str] = {
        "Authorization": f"Bearer {bearer_value(access_token)}",
        "Accept": "application/json",
        **CLIENT_HEADERS,
    }
    if extra:
        headers.update(extra)
    return headers


def chat_headers(access_token: Any) -> dict[str, str]:
    return auth_headers(access_token, {"Content-Type": "application/json", "Accept": "text/event-stream"})


def control_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """控制面（register）请求头：只需客户端标识头 + JSON content-type。"""
    headers: dict[str, str] = {"Content-Type": "application/json", **CLIENT_HEADERS}
    if extra:
        headers.update(extra)
    return headers


def _json_or_empty(response: httpx.Response) -> dict:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def error_detail(text: str) -> str:
    """从错误报文里取出可读文案（``{"error": "..."}`` / ``{"error": {"message": …}}``）。"""
    try:
        payload = json.loads(text)
    except ValueError:
        return text.strip()[:200]
    if not isinstance(payload, dict):
        return text.strip()[:200]
    error = payload.get("error")
    if isinstance(error, str) and error != "":
        return error
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    if isinstance(payload.get("message"), str):
        return payload["message"]
    return text.strip()[:200]


# ── 登录（cline-oauth.ts） ─────────────────────────────────────────────────


async def request_device_authorization() -> dict:
    """``POST {workOsBase}/user_management/authorize/device`` → 归一化设备码信息。"""
    client = await get_client()
    try:
        response = await client.post(
            f"{WORKOS_BASE}{DEVICE_AUTHORIZATION_PATH}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"client_id": WORKOS_CLIENT_ID},
            timeout=CLINE_HTTP_TIMEOUT_S)
    except httpx.HTTPError as error:
        raise UpstreamError(f"cline: 设备码授权网络失败：{error}", CODE["transport"])
    payload = _json_or_empty(response)
    if response.status_code >= 400:
        detail = payload.get("error_description") if isinstance(payload.get("error_description"), str) else ""
        suffix = f" - {detail}" if detail != "" else ""
        raise UpstreamError(f"cline: 设备码授权失败（HTTP {response.status_code}）{suffix}",
                            CODE["server"], status=response.status_code)
    device_code = payload.get("device_code") if isinstance(payload.get("device_code"), str) else ""
    user_code = payload.get("user_code") if isinstance(payload.get("user_code"), str) else ""
    verification_uri = payload.get("verification_uri") if isinstance(payload.get("verification_uri"), str) else ""
    if device_code == "" or user_code == "" or verification_uri == "":
        raise UpstreamError("cline: 设备码授权响应缺少必要字段", CODE["server"], status=response.status_code)
    complete = payload.get("verification_uri_complete")
    return {
        "deviceCode": device_code,
        "userCode": user_code,
        "verificationUri": verification_uri,
        "verificationUriComplete": complete if isinstance(complete, str) and complete != "" else None,
        "expiresInMs": _to_ms(payload.get("expires_in"), DEVICE_AUTH_EXPIRES_MS),
        "intervalMs": _to_ms(payload.get("interval"), DEVICE_AUTH_INTERVAL_MS),
    }


def _to_ms(value: Any, fallback_ms: int) -> int:
    """秒 → 毫秒；非法值回退默认。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        return fallback_ms
    return int(math.floor(value)) * 1000


async def poll_workos_tokens(authorization: dict, *, timeout_s: float | None = None,
                             poll_interval_s: float | None = None) -> dict:
    """轮询直到用户完成授权，返回 ``{accessToken, refreshToken}``。

    状态机（对齐 ``pollWorkOSTokens``）：``authorization_pending`` → 继续；
    ``slow_down`` → interval **累积 +1 秒**后继续；``access_denied`` /
    ``expired_token`` / ``invalid_grant`` → 终态失败；其它非 2xx → 终态失败；
    网络失败容忍 ``POLL_MAX_FAILURES`` 次连续失败。
    """
    client = await get_client()
    window_s = float(timeout_s) if timeout_s else (authorization.get("expiresInMs") or DEVICE_AUTH_EXPIRES_MS) / 1000
    declared = float(poll_interval_s) if poll_interval_s else (authorization.get("intervalMs") or DEVICE_AUTH_INTERVAL_MS) / 1000
    #: 至少 1 秒：服务端可能下发 0 或负数，无节制轮询会被限流。
    interval_s = max(1.0, declared)
    deadline = time.monotonic() + window_s
    failures = 0
    while time.monotonic() <= deadline:
        try:
            response = await client.post(
                f"{WORKOS_BASE}{DEVICE_AUTHENTICATE_PATH}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": DEVICE_CODE_GRANT, "device_code": authorization.get("deviceCode") or "",
                      "client_id": WORKOS_CLIENT_ID},
                timeout=CLINE_HTTP_TIMEOUT_S)
        except httpx.HTTPError as error:
            # 网络抖动：计入连续失败次数，未超额则继续轮询。
            failures += 1
            if failures >= POLL_MAX_FAILURES:
                raise UpstreamError(f"cline: 无法连接 Cline 登录服务（连续 {failures} 次失败）：{error}",
                                    CODE["transport"])
            await asyncio.sleep(interval_s)
            continue
        payload = _json_or_empty(response)
        failures = 0
        if response.status_code < 300:
            access = payload.get("access_token") if isinstance(payload.get("access_token"), str) else ""
            refresh = payload.get("refresh_token") if isinstance(payload.get("refresh_token"), str) else ""
            if access == "" or refresh == "":
                # 2xx 却缺令牌：服务端异常（不是「等用户」），避免死循环。
                raise UpstreamError("cline: WorkOS token 响应缺少必要字段", CODE["server"],
                                    status=response.status_code)
            return {"accessToken": access, "refreshToken": refresh}
        error_code = payload.get("error") if isinstance(payload.get("error"), str) else ""
        if error_code == "authorization_pending":
            # ⚠️ **不是错误**：用户还没在浏览器里点授权。
            await asyncio.sleep(interval_s)
            continue
        if error_code == "slow_down":
            interval_s += 1.0
            await asyncio.sleep(interval_s)
            continue
        detail = payload.get("error_description") if isinstance(payload.get("error_description"), str) else ""
        if error_code in ("access_denied", "expired_token", "invalid_grant"):
            raise UpstreamError(f"cline: {detail or 'WorkOS 授权失败'}", CODE["credential"],
                                status=response.status_code)
        suffix = f" - {detail}" if detail != "" else ""
        raise UpstreamError(f"cline: WorkOS token 轮询失败（HTTP {response.status_code}）{suffix}",
                            CODE["server"], status=response.status_code)
    raise UpstreamError("cline: 登录等待已超时，请重新发起登录", CODE["timeout"])


async def register_tokens(work_os_tokens: dict) -> Any:
    """``POST {apiBase}/api/v1/auth/register``：WorkOS token 换 Cline 自己的 token。

    请求体字段是**驼峰** ``accessToken`` / ``refreshToken``；响应套 ``{success, data}``。
    """
    client = await get_client()
    try:
        response = await client.post(
            f"{API_BASE}{REGISTER_PATH}",
            headers=control_headers(),
            content=json.dumps({"accessToken": work_os_tokens.get("accessToken") or "",
                                "refreshToken": work_os_tokens.get("refreshToken") or ""}).encode("utf-8"),
            timeout=CLINE_HTTP_TIMEOUT_S)
    except httpx.HTTPError as error:
        raise UpstreamError(f"cline: token 注册网络失败：{error}", CODE["transport"])
    if response.status_code >= 400:
        raise UpstreamError(f"cline: token 注册失败（HTTP {response.status_code}）：{error_detail(response.text)}",
                            CODE["server"], status=response.status_code)
    return _json_or_empty(response)


def _open_external(url: str) -> bool:
    """用系统默认浏览器打开 URL；永不抛错。"""
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


async def run_login(*, open_browser: bool = True, timeout_s: float | None = None,
                    poll_interval_s: float | None = None) -> dict:
    """完整登录：取设备码 → 打开浏览器 → 轮询 WorkOS token → 注册 Cline token。

    阻塞语义：等用户完成授权后才返回。设备码流程不起本地端口。
    """
    authorization = await request_device_authorization()
    login_url = authorization.get("verificationUriComplete") or authorization["verificationUri"]
    if open_browser:
        _open_external(login_url)
    tokens = await poll_workos_tokens(authorization, timeout_s=timeout_s, poll_interval_s=poll_interval_s)
    registered = await register_tokens(tokens)
    payload = parse_token_payload(registered)
    if payload.get("accessToken", "") == "":
        raise UpstreamError("cline: 登录响应缺少访问令牌", CODE["credential"])
    credential = build_credential(payload)
    credential["login_url"] = login_url
    credential["user_code"] = authorization.get("userCode") or ""
    return credential


# ── 续期（cline-auth.ts 的 refreshCredential） ──────────────────────────────


async def refresh_credential(credential: dict) -> dict:
    """``POST {apiBase}/api/v1/auth/refresh``：``refresh_token`` 换新令牌。

    终态判定与 TS 一致：传输层失败与 5xx / 429 属**可重试**（报服务端/传输码），
    401 / 403 与「200 却缺令牌」属**终态**（报凭据码，需重新登录）。
    """
    if not is_refreshable(credential):
        raise UpstreamError("cline: 无 refresh_token，请重新登录", CODE["credential"])
    client = await get_client()
    try:
        response = await client.post(
            f"{API_BASE}{REFRESH_PATH}",
            headers=control_headers({"Accept": "application/json"}),
            content=json.dumps(cline_refresh_body(credential)).encode("utf-8"),
            timeout=CLINE_HTTP_TIMEOUT_S)
    except httpx.HTTPError as error:
        # 传输层失败**不能**判为终态 —— 网络抖动不该让用户重新登录。
        raise UpstreamError(f"cline: 续期网络失败：{error}", CODE["transport"])
    if response.status_code in (401, 403):
        raise UpstreamError(f"cline: 续期被拒绝（HTTP {response.status_code}），请重新登录",
                            CODE["credential"], status=response.status_code)
    if response.status_code >= 400:
        raise UpstreamError(f"cline: 续期失败（HTTP {response.status_code}）：{response.text[:200]}",
                            CODE["server"], status=response.status_code)
    payload = parse_token_payload(_json_or_empty(response))
    if payload.get("accessToken", "") == "":
        raise UpstreamError("cline: 续期响应缺少访问令牌，请重新登录", CODE["credential"],
                            status=response.status_code)
    return apply_refresh(credential, payload)


# ── 模型目录（cline-models.ts） ─────────────────────────────────────────────


def parse_entry_list(value: Any) -> list[dict]:
    """把远端数组归一化（丢弃无 id 的垃圾项）。"""
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id").strip() if isinstance(item.get("id"), str) else ""
        if model_id == "":
            continue
        row: dict = {"id": model_id}
        name = item.get("name").strip() if isinstance(item.get("name"), str) else ""
        if name != "":
            row["name"] = name
        description = item.get("description").strip() if isinstance(item.get("description"), str) else ""
        if description != "":
            row["description"] = description
        out.append(row)
    return out


def parse_recommended_models(value: Any) -> dict:
    """解析 ``recommended-models`` 响应（``free`` / ``recommended`` / ``clinePass``）。

    ⚠️ ``clinePass`` **不是免费集合**（订阅制 ``cline-pass/*``），只是保证可发现性。
    """
    if not isinstance(value, dict):
        return {"free": [], "recommended": [], "clinePass": []}
    return {
        "free": parse_entry_list(value.get("free")),
        "recommended": parse_entry_list(value.get("recommended")),
        "clinePass": parse_entry_list(value.get("clinePass")),
    }


def parse_remote_model_ids(value: Any) -> list[str]:
    """解析 ``/api/v1/models`` 响应（``{"data":[{id,…}]}``）的 id 列表。"""
    if not isinstance(value, dict):
        return []
    data = value.get("data")
    if not isinstance(data, list):
        return []
    ids: list[str] = []
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"].strip() != "":
            ids.append(item["id"].strip())
    return ids


def merge_models(remote: dict) -> list[dict]:
    """合并三个来源（远端 free / 兜底表 / 远端其余 id），对齐 ``mergeClineModels``。

    顺序：免费模型在前 → 兜底表其余条目 → ``recommended``/``clinePass`` →
    远端 ``/models`` 的其余 id（460 个，只有裸 id，放最后）。

    ⚠️ 兜底表**不是无条件并入**：远端成功下发目录（``entries`` 非空）时，兜底表里
    远端已不认识的条目会被丢弃 —— 那意味着模型已被上游下架，并回列表会让用户
    看到一个标着「免费」的模型、选中却回 404。
    """
    free_ids = remote.get("freeIds") or []
    remote_ids = remote.get("remoteIds") or []
    entries = remote.get("entries") or []
    free_set = set(free_ids)
    entry_index = {entry["id"]: entry for entry in entries}
    known: set[str] | None = None
    if entries:
        known = set(free_ids) | {entry["id"] for entry in entries} | set(remote_ids)
    seen: set[str] = set()
    out: list[dict] = []

    def build(model_id: str) -> dict:
        fallback = FALLBACK_INDEX.get(model_id) or {}
        entry = entry_index.get(model_id) or {}
        is_free = is_free_model(model_id, free_set, fallback)
        name = fallback.get("name") or entry.get("name") or display_name(model_id)
        row: dict = {
            "id": model_id,
            "name": with_free_mark(name, is_free),
            "isFree": is_free,
            # Cline 全模型共用一张档位表（远端不下发档位），故恒为 True。
            "reasoning": True,
        }
        if fallback.get("contextWindow") is not None:
            row["contextWindow"] = fallback["contextWindow"]
        if fallback.get("maxTokens") is not None:
            row["maxOutput"] = fallback["maxTokens"]
        if fallback.get("supportsImage") is not None:
            row["vision"] = bool(fallback["supportsImage"])
        description = entry.get("description") or fallback.get("description")
        if isinstance(description, str) and description != "":
            row["description"] = description
        return row

    def push(model_id: str) -> None:
        if model_id in seen:
            return
        seen.add(model_id)
        out.append(build(model_id))

    for model_id in free_ids:
        push(model_id)
    for model in FALLBACK_MODELS:
        if known is not None and model["id"] not in known:
            continue
        push(model["id"])
    for entry in entries:
        push(entry["id"])
    for model_id in remote_ids:
        push(model_id)
    return out


def fallback_catalog() -> list[dict]:
    """内置兜底表（远端不可用时的**整表**兜底）。"""
    return merge_models({"freeIds": [], "remoteIds": [], "entries": []})


async def fetch_models(credential: dict) -> dict:
    """两个端点独立容错地拉取目录；**任何失败都不抛错**，最差返回内置兜底表。

    - ``GET /api/v1/ai/cline/recommended-models``：唯一权威的 ``free`` 集合，**无需认证**；
    - ``GET /api/v1/models``：460 个 id，**需要认证**（无凭据时不发，省一条无谓的 401）。
    """
    client = await get_client()
    free_ids: list[str] = []
    remote_ids: list[str] = []
    entries: list[dict] = []
    warnings: list[str] = []

    try:
        response = await client.get(f"{API_BASE}{RECOMMENDED_MODELS_PATH}",
                                    headers={"Accept": "application/json", **CLIENT_HEADERS},
                                    timeout=MODELS_TIMEOUT_S)
        if response.status_code >= 400:
            warnings.append(f"recommended-models HTTP {response.status_code}")
        else:
            parsed = parse_recommended_models(_json_or_empty(response))
            free_ids = [entry["id"] for entry in parsed["free"]]
            entries = [*parsed["free"], *parsed["recommended"], *parsed["clinePass"]]
    except Exception as error:  # noqa: BLE001
        warnings.append(f"recommended-models {error}")

    access_token = credential.get("access_token") if isinstance(credential, dict) else None
    if isinstance(access_token, str) and access_token != "":
        try:
            response = await client.get(f"{API_BASE}{MODELS_PATH}", headers=auth_headers(access_token),
                                        timeout=MODELS_TIMEOUT_S)
            if response.status_code >= 400:
                warnings.append(f"models HTTP {response.status_code}")
            else:
                remote_ids = parse_remote_model_ids(_json_or_empty(response))
        except Exception as error:  # noqa: BLE001
            warnings.append(f"models {error}")

    models = merge_models({"freeIds": free_ids, "remoteIds": remote_ids, "entries": entries})
    if not models:
        models = fallback_catalog()
    result: dict = {"models": models, "at": int(time.time() * 1000)}
    if warnings:
        result["warnings"] = warnings
    return result


# ── 推理（cline-adapter.ts 的 stream） ─────────────────────────────────────

#: 额度/限流文案标记（中英双通道；网关在不同层可能给出不同文案）。
CREDIT_MARKERS: tuple[str, ...] = (
    "insufficient", "quota", "rate limit", "too many requests", "balance",
    "credit", "payment required", "exceeded",
    "积分不足", "额度不足", "余额不足", "频率限制", "超出限制",
)

#: 地域/访问限制文案标记（小写比对）。403 里既有真的凭据问题也有地域限制，
#: 只能靠响应体文案区分；命中时**跳过续期**（续期在这里永远无用）。
REGION_FORBIDDEN_MARKERS: tuple[str, ...] = (
    "not available in your region",
    "access forbidden",
    "region not supported",
    "not available in your country",
)


def is_region_forbidden(status: int, body: str) -> bool:
    if status != 403:
        return False
    lower = body.lower()
    return any(marker in lower for marker in REGION_FORBIDDEN_MARKERS)


def clamp_max_tokens(value: Any) -> int | None:
    """收敛输出上限到安全区间；非法值返回 None（不编造）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    integer = int(math.floor(value))
    if integer <= 0:
        return None
    return min(integer, MAX_OUTPUT_TOKENS)


def sanitize_tool_parameters(value: Any) -> Any:
    """递归删除工具参数 schema 里的空字符串 ``enum`` 成员。

    上游 harness 的工具集里某些参数 ``enum`` 含空串成员，Gemini 系模型会直接 400
    （``enum[3]: cannot be empty``）。只删空串，其余成员原样保留；过滤后为空则整个
    ``enum`` 键丢弃（空 ``enum`` 同样非法）。
    """
    if isinstance(value, list):
        return [sanitize_tool_parameters(item) for item in value]
    if not isinstance(value, dict):
        return value
    out: dict = {}
    for key, raw in value.items():
        if key == "enum" and isinstance(raw, list):
            cleaned = [item for item in raw if not (isinstance(item, str) and item.strip() == "")]
            if cleaned:
                out[key] = cleaned
            continue
        out[key] = sanitize_tool_parameters(raw)
    return out


def serialize_tools(tools: Any) -> list[dict]:
    """把入参工具（内部形状 ``{name, description, parameters}`` 或 OpenAI 形状）转为 wire 形状。"""
    out: list[dict] = []
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = fn.get("name")
        if not isinstance(name, str) or name.strip() == "":
            continue
        parameters = fn.get("parameters")
        out.append({"type": "function", "function": {
            "name": name,
            "description": fn.get("description") or "",
            "parameters": sanitize_tool_parameters(
                parameters if isinstance(parameters, dict) else {"type": "object", "properties": {}}),
        }})
    return out


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "".join(str(block.get("text") or "") for block in content
                   if isinstance(block, dict) and block.get("type") == "text")


def serialize_messages(messages: Any) -> list[dict]:
    """消息序列化（对齐共享的 ``serializeMessages``）。

    两条入参形状都要认：

    - **OpenAI 形状**（管理器按 ``openai`` 请求体直接分派，最常见）：``tool_calls``
      原样透传，正文为空且有工具调用时 ``content`` 置 ``None``；
    - **内部块形状**：``content`` 里的 ``text`` 块折叠为正文、``reasoning`` 块折叠进
      **``reasoning``**（该渠道认的思考字段名，见模块头第 2 条）、``tool-call`` 块
      折叠回 OpenAI 的 ``tool_calls``。

    ⚠️ 内部块形状里 assistant 的思考**不写成** ``reasoning_content`` —— Cline 只认
    ``reasoning``，写错名字等于把历史思考整段丢掉。
    """
    if not isinstance(messages, list):
        return []
    wire: list[dict] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") != "assistant":
            wire.append(message)
            continue
        content = message.get("content")
        text = content if isinstance(content, str) else _content_text(content)
        reasoning = message.get("reasoning") if isinstance(message.get("reasoning"), str) else ""
        if reasoning == "" and isinstance(message.get("reasoning_content"), str):
            reasoning = message["reasoning_content"]
        blocks = content if isinstance(content, list) else []
        if reasoning == "":
            reasoning = "".join(str(block.get("text") or "") for block in blocks
                                if isinstance(block, dict) and block.get("type") == "reasoning")
        tool_calls = list(message.get("tool_calls")) if isinstance(message.get("tool_calls"), list) else []
        if not tool_calls:
            for block in blocks:
                if not isinstance(block, dict) or block.get("type") != "tool-call":
                    continue
                name = block.get("name")
                if not isinstance(name, str) or name.strip() == "":
                    continue
                arguments = block.get("arguments")
                tool_calls.append({"id": str(block.get("id") or ""), "type": "function",
                                   "function": {"name": name,
                                                "arguments": arguments if isinstance(arguments, str) else "{}"}})
        entry: dict[str, Any] = {
            "role": "assistant",
            "content": None if (text == "" and tool_calls) else text,
        }
        if reasoning != "":
            entry["reasoning"] = reasoning
        if tool_calls:
            entry["tool_calls"] = tool_calls
        wire.append(entry)
    return wire


def build_payload(body: dict, model_id: str) -> dict:
    """构造上游请求体（字段名与 ``cline-adapter.ts`` 的 ``bodyObj`` 一致）。"""
    payload: dict = {
        "model": model_id,
        "messages": serialize_messages(body.get("messages")),
        "stream": True,
    }
    tools = serialize_tools(body.get("tools"))
    if tools:
        payload["tools"] = tools
    temperature = body.get("temperature")
    if isinstance(temperature, (int, float)) and not isinstance(temperature, bool):
        payload["temperature"] = temperature
    max_tokens = clamp_max_tokens(body.get("max_tokens"))
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    stop = body.get("stop")
    if isinstance(stop, list) and stop:
        payload["stop"] = stop
    # 推理强度：调用方的值**原样透传**。⚠️ 绝不加白名单校验 —— 档位表是客户端内嵌
    # 目录的快照，会随 Cline 版本变化；且上游对不认识的档位静默忽略（实测
    # `reasoning_effort: 'banana'` 返回 200 且思考量为 0），校验只会静默丢档位。
    effort = body.get("reasoning_effort")
    if effort is not None:
        payload["reasoning_effort"] = effort
    return payload


def _error_code(status: int, text: str) -> str:
    """失败归类：限流/额度 → quota；401/403 → 凭据；5xx → 服务端；其余 4xx → 客户端。"""
    lower = text.lower()
    if status in (429, 402) or any(marker in lower for marker in CREDIT_MARKERS):
        return CODE["quota"]
    if status in (401, 403):
        return CODE["credential"]
    if status >= 500:
        return CODE["server"]
    return CODE["client"]


async def _send_chat(client: httpx.AsyncClient, access_token: Any, data: bytes, url: str):
    """发一次 chat 请求；网络失败映射为可重试的 TRANSPORT 失败。"""
    try:
        return await client.send(client.build_request("POST", url, headers=chat_headers(access_token),
                                                      content=data), stream=True)
    except httpx.HTTPError as error:
        raise UpstreamError(f"cline: transport error: {error}", CODE["transport"])


def _usage_chunk(raw: Any) -> dict:
    """把 ``read_stream`` 汇总的 usage 投影成内部 ``usage`` chunk。

    字段名照抄本项目约定：``inputTokens`` 只含**未缓存**输入，缓存命中单列
    ``cacheReadTokens``；``reasoningTokens`` 恒存在（缺省 0）。
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

    - 工具参数残缺（``brokenToolCall``）→ ``max-tokens``（报 ``tool-calls`` 会让
      harness 执行半截 JSON 参数，模型随后陷入重试循环）；
    - 有工具调用却没收到 ``finish_reason`` → ``max-tokens``（连接被掐断）；
    - 其余按 ``finish_reason`` 的既有映射（``length`` → ``max-tokens``、
      ``tool_calls`` → ``tool-calls``、其余 → ``stop``）；
    - 零块 + ``stop`` → ``error``（``EMPTY_RESPONSE``）：不许静默结束。
    """
    if state.get("brokenToolCall") is True:
        kind = "max-tokens"
    elif state.get("sawToolCall") is True and state.get("sawFinish") is not True:
        kind = "max-tokens"
    else:
        token = state.get("finish") if isinstance(state.get("finish"), str) else None
        kind = finish_reason(token)["kind"]
    if kind == "stop" and blocks == 0:
        return {"kind": "error",
                "failure": {"message": "model returned a completed response with no content",
                            "code": CODE["empty"]}}
    return {"kind": kind}


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """POST 一轮 ``/api/v1/chat/completions`` 并以内部 chunk 产出。

    SSE 的逐帧解析与块组装交给 ``read_stream``（``wire="chat"``）：
    ``delta.reasoning`` 走 ``reasoning-delta``（该渠道的思考字段名，见模块头第 2 条），
    ``tool_calls`` 按 ``index`` 合并后走 ``tool-call-delta``，收尾由本函数补
    ``usage`` 与 ``finish``。401/403 先排除地域限制，再静默续期一次后原样重发。
    ``catalog`` 本渠道不使用（每轮直发 ``model``），保留形参以对齐渠道约定。
    """
    model_id = str(body.get("model") or "")
    data = json.dumps(build_payload(body, model_id), ensure_ascii=False).encode("utf-8")
    url = f"{API_BASE}{CHAT_PATH}"
    channel = create_channel()
    client = await get_client()

    async def produce() -> None:
        nonlocal credential
        response = None
        try:
            response = await _send_chat(client, credential.get("access_token"), data, url)
            if response.status_code in (401, 403):
                text = (await response.aread()).decode("utf-8", "replace")
                await response.aclose()
                response = None
                # ⚠️ **403 必须先排除「地域限制」**：它与凭据无关，续期在这里永远无用，
                # 且最终会被归成凭据错误（UI 显示「密钥无效」），真实原因彻底丢失。
                # 实测：403 {"error":"access forbidden: cline-free/… is not available in your region"}
                if is_region_forbidden(403, text):
                    raise UpstreamError(f"cline: {error_detail(text)}", CODE["region"], status=403)
                refreshed = await refresh_credential(credential)
                credential = refreshed
                if on_refresh is not None:
                    on_refresh(refreshed)
                response = await _send_chat(client, credential.get("access_token"), data, url)
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                if is_region_forbidden(response.status_code, text):
                    raise UpstreamError(f"cline: {error_detail(text)}", CODE["region"],
                                        status=response.status_code)
                raise UpstreamError(f"cline: HTTP {response.status_code} {text[:200]}",
                                    _error_code(response.status_code, text), status=response.status_code)
            head = await read_head(response.aiter_bytes(), 4096, STREAM_TIMEOUT_S)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("cline: empty model response body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), channel.push, STREAM_TIMEOUT_S)
            else:
                text = (await _read_remainder(head)).decode("utf-8", "replace")
                try:
                    parsed = json.loads(text)
                except ValueError:
                    raise UpstreamError("cline: unexpected non-stream response", CODE["server"])
                if isinstance(parsed, dict) and parsed.get("error"):
                    raise UpstreamError(f"cline: {error_detail(text)}", CODE["server"])
                channel.push(json.dumps(parsed, ensure_ascii=False))
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
