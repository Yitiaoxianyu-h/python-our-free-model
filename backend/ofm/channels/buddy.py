"""CodeBuddy（腾讯 CodeBuddy / genie 扩展，external-link-v2 轮询式登录）渠道。

移植自原版 channel-pack 的 ``buddy.ts`` / ``buddy-oauth.ts`` / ``buddy-adapter.ts`` /
``product.ts``（中国版 ``CODEBUDDY`` 产品配置）。SSE 解析走 ``..stream.read_stream``
（等价原版 ``sse.ts`` 的语义），故本模块只负责「端点 + 鉴权头 + 请求体 + 登录流程」。

与 CodeArts 的 PKCE OAuth + 本地回调服务器**不同**，CodeBuddy 采用**轮询式**登录：
客户端不起本地服务器，而是

1. ``POST /v2/plugin/auth/state?platform=ide`` → 取 ``state`` + ``authUrl``（无需认证）；
2. 打开浏览器到 ``authUrl``（``https://www.codebuddy.cn/login/?platform=ide&state=...``）；
3. 轮询 ``GET /v2/plugin/auth/token?state=...``（1s 间隔，5 分钟超时）取令牌；
   错误码 ``11217`` = 尚未就绪 → 继续轮询，网络错误同样继续（不中断登录）；
4. 轮询 ``GET /v2/plugin/login/account?state=...``（需 Bearer）取账户信息；
   错误码 ``12151`` = 账户信息尚未完成 → 继续轮询。

推理：``POST https://copilot.tencent.com/v2/chat/completions``，标准 OpenAI Chat
Completions 协议 + ``Authorization: Bearer <access_token>``；思考为
``delta.reasoning_content``，工具调用为 ``delta.tool_calls``（按 ``index`` 合并）。

模型目录三层回退（``buddy-oauth.ts`` 的 ``fetchModels``）：
scoped 端点 ``/console/enterprises/personal/models`` → ``/v3/config`` → 内置兜底表；
任何一层失败都不抛错（兜底表对齐 ``product.ts`` 的 ``CODEBUDDY_FALLBACK_MODELS``）。
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import re
import secrets
import time
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import read_stream

CHANNEL_ID = "buddy"

# ── 端点与常量（buddy.ts / product.ts 的 CODEBUDDY） ────────────────────────

API_ENDPOINT = "https://copilot.tencent.com"
PREFIX_PATH = "/plugin"
PLATFORM = "ide"
WEBSITE_HOME = "https://www.codebuddy.cn"

AUTH_STATE_PATH = "/v2/plugin/auth/state"
AUTH_TOKEN_PATH = "/v2/plugin/auth/token"
LOGIN_ACCOUNT_PATH = "/v2/plugin/login/account"
AUTH_REFRESH_PATH = "/v2/plugin/auth/token/refresh"
ACCOUNTS_PATH = "/v2/plugin/accounts"
CONFIG_PATH = "/v3/config"

CHAT_PATH = "/v2/chat/completions"
ENTERPRISE_MODELS_SCOPE = "personal"

#: 轮询参数（与 IDE 的 5*60*1e3 / setTimeout(o,1e3) 对齐）。
LOGIN_TIMEOUT_S = 5 * 60
POLL_INTERVAL_S = 1.0
#: auth/state 请求超时（10s；原版曾为 5s，实测不够后被放宽）。
STATE_REQUEST_TIMEOUT_S = 10.0
#: 其余控制面请求超时（token / account / refresh / config）。
REQUEST_TIMEOUT_S = 60.0
STREAM_TIMEOUT_S = 600.0

#: 错误码（逆向自 IDE catch 分支）。
CODE_TOKEN_NOT_READY = 11217
CODE_ACCOUNT_NOT_READY = 12151

# ── HTTP 头名（buddy.ts 的 HTTP_HEADER_*） ─────────────────────────────────

HTTP_HEADER_DOMAIN = "X-Domain"
HTTP_HEADER_ENTERPRISE_ID = "X-Enterprise-Id"
HTTP_HEADER_TENANT_ID = "X-Tenant-Id"
HTTP_HEADER_NO_AUTHORIZATION = "X-No-Authorization"
HTTP_HEADER_NO_USER_ID = "X-No-User-Id"
HTTP_HEADER_NO_ENTERPRISE_ID = "X-No-Enterprise-Id"
HTTP_HEADER_NO_DEPARTMENT_INFO = "X-No-Department-Info"
HTTP_HEADER_REFRESH_TOKEN = "X-Refresh-Token"
HTTP_HEADER_AUTH_REFRESH_SOURCE = "X-Auth-Refresh-Source"
HTTP_HEADER_PRODUCT = "X-Product"
HTTP_HEADER_PRODUCT_CODE = "X-Product-Code"

#: IDE 客户端标识（getUserAgent() → CodeBuddyIDE/${product.json version}）。
BUDDY_USER_AGENT = "CodeBuddyIDE/1.106.1"
BUDDY_PRODUCT_CODE = "codebuddy"
#: X-Product 在模型目录请求里是**部署类型**（SaaS）；在 chat 请求里是**归属名**。
BUDDY_DEPLOYMENT_TYPE = "SaaS"
AUTH_REFRESH_SOURCE = "ide-main"
API_DOMAIN = "copilot.tencent.com"
#: 用量归属头族取值（product.ts 的 CODEBUDDY.attributionName / clientVersion）。
ATTRIBUTION_NAME = "CodeBuddy"
CLIENT_VERSION = "1.106.1"

#: 前缀缓存会话标识（prompt_cache_key）；调用方未给时复用同一个进程级 key。
_SESSION_ID = secrets.token_hex(16)

# ── 模型（product.ts 的 CODEBUDDY_FALLBACK_MODELS） ────────────────────────

FALLBACK_MODELS: list[dict] = [
    {"id": "hy4-preview", "name": "Hy4 preview", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["high"], "defaultReasoningEffort": "high", "maxOutput": 64_000},
    {"id": "hy3", "name": "Hy3", "contextWindow": 192_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high"], "defaultReasoningEffort": "high", "maxOutput": 64_000},
    {"id": "hy3-x", "name": "Hy3", "contextWindow": 192_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high"], "defaultReasoningEffort": "high", "maxOutput": 64_000},
    {"id": "deepseek-v4.1-flash", "name": "Deepseek-V4.1-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high", "max"], "defaultReasoningEffort": "high",
     "maxOutput": 128_000},
    {"id": "deepseek-v4-pro", "name": "Deepseek-V4-Pro", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high", "xhigh"], "defaultReasoningEffort": "high",
     "maxOutput": 128_000},
    {"id": "deepseek-v4-flash", "name": "Deepseek-V4-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high", "max"], "defaultReasoningEffort": "high",
     "maxOutput": 50_000},
    {"id": "glm-5.3", "name": "GLM-5.3", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high", "max"], "defaultReasoningEffort": "high",
     "maxOutput": 64_000},
    {"id": "glm-5.3-flash", "name": "GLM-5.3-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high", "max"], "defaultReasoningEffort": "high",
     "maxOutput": 32_000},
    {"id": "glm-5.2", "name": "GLM-5.2", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["high", "xhigh"], "defaultReasoningEffort": "high",
     "maxOutput": 64_000},
    {"id": "glm-5.1", "name": "GLM-5.1", "contextWindow": 200_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["medium"], "maxOutput": 48_000},
    {"id": "glm-5v-turbo", "name": "GLM-5V-Turbo", "contextWindow": 200_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["medium"], "maxOutput": 64_000},
    {"id": "kimi-k3-1", "name": "Kimi-K3-1", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["medium"], "maxOutput": 32_000},
    {"id": "kimi-k2.8-preview", "name": "Kimi-K2.8-Preview", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["low", "high", "max"], "defaultReasoningEffort": "high",
     "maxOutput": 64_000},
    {"id": "kimi-k2.7", "name": "Kimi-K2.7", "contextWindow": 256_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["medium"], "maxOutput": 32_000},
    {"id": "kimi-k2.6", "name": "Kimi-K2.6", "contextWindow": 256_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["medium"], "maxOutput": 32_000},
    {"id": "minimax-m3", "name": "MiniMax-M3", "contextWindow": 512_000, "vision": True,
     "reasoning": True, "reasoningEfforts": ["medium"], "maxOutput": 64_000},
]

FALLBACK_INDEX: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS}
CONTEXT_WINDOWS: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS}

#: 已知模型 ID → 展示名（buddy.ts 的 MODEL_DISPLAY_NAMES）。
MODEL_DISPLAY_NAMES: dict[str, str] = {
    "deepseek-v4-flash": "DeepSeek V4 Flash",
    "deepseek-v4-pro": "DeepSeek V4 Pro",
    "hy4-preview": "Hy4 Preview",
    "hy4-preview-x": "Hy4 Preview X",
    "hy3": "Hy3",
    "hy3-x": "Hy3 X",
    "glm-5.3": "GLM-5.3",
    "glm-5.3-flash": "GLM-5.3 Flash",
    "glm-5.2": "GLM-5.2",
    "glm-5.1": "GLM-5.1",
    "glm-5v-turbo": "GLM-5V Turbo",
    "kimi-k3-1": "Kimi K3-1",
    "kimi-k2.7": "Kimi K2.7",
    "kimi-k2.6": "Kimi K2.6",
    "minimax-m3": "MiniMax M3",
}

#: 模型是否接受图片输入（buddy-adapter.ts 的 IMAGE_MODELS；远端未下发时的兜底）。
IMAGE_MODELS = {
    "deepseek-v4-flash", "deepseek-v4.1-flash", "deepseek-v4.1-flash-sg", "deepseek-v4-pro",
    "hy4-preview", "hy4-preview-f", "hy4-preview-x", "hy3", "hy3-x",
    "glm-5.3", "glm-5.3-flash", "glm-5.2", "glm-5.1", "glm-5v-turbo",
    "kimi-k3", "kimi-k3-1", "kimi-k2.8-preview", "kimi-k2.7", "kimi-k2.6", "minimax-m3",
}

#: 可选思考等级（buddy-adapter.ts 的 REASONING_EFFORTS；远端未下发时的兜底）。
ADAPTER_REASONING_EFFORTS: dict[str, list[str]] = {
    "deepseek-v4-flash": ["low", "high", "max"],
    "deepseek-v4.1-flash": ["low", "high", "max"],
    "deepseek-v4-pro": ["low", "high", "xhigh"],
    "hy4-preview": ["high"],
    "hy4-preview-x": ["high"],
    "hy3": ["low", "high"],
    "hy3-x": ["low", "high"],
    "glm-5.3": ["low", "high", "max"],
    "glm-5.3-flash": ["low", "high", "max"],
    "glm-5.2": ["high", "xhigh"],
}

#: 「可选对话模型清单」的 agent 名，按优先级排列（buddy.ts 的 PREFERRED_AGENT_NAMES）。
PREFERRED_AGENT_NAMES = ("cli", "craft")

# ── 纯解析：字段读取（buddy.ts） ───────────────────────────────────────────

_CONTROL_CHARS = re.compile(r"[\u0000-\u001F\u007F]+")
_WHITESPACE_RUN = re.compile(r"\s{2,}")
_NUMBER_TEXT = re.compile(r"^-?\d+(\.\d+)?$")


def strip_control_chars(value: str) -> str:
    """去掉控制字符（含 CR/LF/Tab）并把连续空白折叠为单个空格。"""
    return _WHITESPACE_RUN.sub(" ", _CONTROL_CHARS.sub(" ", value)).strip()


def read_string_field(data: Any, key: str) -> str:
    """安全读取字符串字段（兼容后端把时间戳返回为数字；剔除控制字符）。"""
    if not isinstance(data, dict):
        return ""
    value = data.get(key)
    if isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return strip_control_chars(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return str(value)
    return ""


def read_number_field(data: Any, key: str) -> float | None:
    """读取数值字段（兼容数字型字符串）。"""
    if not isinstance(data, dict):
        return None
    value = data.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    if isinstance(value, str) and _NUMBER_TEXT.match(value.strip()):
        return float(value.strip())
    return None


def _jwt_payload(token: Any) -> dict | None:
    """只做 base64url 解码、不验签（该值仅用于展示与续期调度）。"""
    if not isinstance(token, str) or token == "":
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return payload if isinstance(payload, dict) else None


def jwt_expires_at_ms(token: Any) -> int | None:
    payload = _jwt_payload(token)
    if payload is None:
        return None
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool) and math.isfinite(exp):
        return int(exp * 1000)
    return None


def jwt_issued_at_ms(token: Any) -> int | None:
    payload = _jwt_payload(token)
    if payload is None:
        return None
    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and not isinstance(iat, bool) and math.isfinite(iat):
        return int(iat * 1000)
    return None


def jwt_nickname(token: Any) -> str:
    """昵称只在 access_token 的声明里（login/account 响应常为空）。"""
    payload = _jwt_payload(token)
    if payload is None:
        return ""
    for key in ("nickname", "preferred_username", "name"):
        value = payload.get(key)
        if isinstance(value, str):
            return strip_control_chars(value)
    return ""


def jwt_subject(token: Any) -> str:
    payload = _jwt_payload(token)
    if payload is None:
        return ""
    sub = payload.get("sub")
    return sub if isinstance(sub, str) else ""


def credential_expires_at_ms(credential: dict) -> int | None:
    """解析凭据过期时刻（毫秒）；无法解析时回退 access_token 的 JWT ``exp``。"""
    raw = credential.get("expires_at") if isinstance(credential, dict) else None
    if isinstance(raw, str) and raw != "":
        if raw.isdigit():
            value = int(raw)
            return value if value > 1_000_000_000_000 else value * 1000
        parsed = _parse_iso_ms(raw)
        if parsed is not None:
            return parsed
    return jwt_expires_at_ms((credential or {}).get("access_token") if isinstance(credential, dict) else None)


def _parse_iso_ms(value: str) -> int | None:
    from datetime import datetime

    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return int(parsed.timestamp() * 1000)


def is_expired(credential: dict) -> bool:
    """无法解析过期时间时**不判定过期**（对齐 Rust is_expired）。"""
    expires_at = credential_expires_at_ms(credential)
    return False if expires_at is None else int(time.time() * 1000) >= expires_at


def is_refreshable(credential: dict) -> bool:
    token = credential.get("refresh_token") if isinstance(credential, dict) else None
    return isinstance(token, str) and token != ""


def _absolute_expiry_ms(record: dict, absolute_key: str, relative_key: str, access_token: str) -> str:
    """绝对字段缺失时用相对秒数（``expiresIn``）换算，基准取 access_token 的 ``iat``。"""
    absolute = read_string_field(record, absolute_key)
    if absolute != "":
        if absolute.isdigit():
            as_number = int(absolute)
            if as_number > 1_000_000_000_000:
                return str(as_number)
            return str(as_number * 1000)
        parsed = _parse_iso_ms(absolute)
        if parsed is not None:
            return str(parsed)
        return absolute
    relative = read_number_field(record, relative_key)
    if relative is None:
        # 无相对值：交给 JWT exp 兜底（access_token 的 exp 即权威过期时刻）。
        return ""
    base_ms = jwt_issued_at_ms(access_token)
    if base_ms is None:
        base_ms = int(time.time() * 1000)
    return str(base_ms + int(relative * 1000))


def parse_token_data(data: Any) -> dict:
    """解析 ``auth/token``（含 refresh）响应；只返回相对秒数时换算为绝对毫秒。"""
    record = data if isinstance(data, dict) else {}
    token_type = read_string_field(record, "tokenType")
    access_token = read_string_field(record, "accessToken")
    return {
        "accessToken": access_token,
        "refreshToken": read_string_field(record, "refreshToken"),
        "expiresAt": _absolute_expiry_ms(record, "expiresAt", "expiresIn", access_token),
        "refreshExpiresAt": _absolute_expiry_ms(record, "refreshExpiresAt", "refreshExpiresIn", access_token),
        "tokenType": token_type if token_type != "" else "Bearer",
        "scope": read_string_field(record, "scope"),
        "domain": read_string_field(record, "domain"),
    }


def parse_account_data(data: Any) -> dict:
    """解析 ``login/account`` 响应（昵称常为空，真正的昵称在 JWT 声明里）。"""
    record = data if isinstance(data, dict) else {}
    account_type = read_string_field(record, "type")
    return {
        "uid": read_string_field(record, "uid"),
        "nickname": read_string_field(record, "nickname"),
        "enterpriseId": read_string_field(record, "enterpriseId"),
        "accountType": account_type if account_type != "" else "personal",
    }


def build_credential(token: dict, account: dict) -> dict:
    """组合令牌与账户数据为可持久化凭据（昵称/UID 缺失时回填 JWT 声明）。"""
    access_token = token.get("accessToken") or ""
    nickname = account.get("nickname") or ""
    if nickname == "":
        nickname = jwt_nickname(access_token)
    uid = account.get("uid") or ""
    if uid == "":
        uid = jwt_subject(access_token)
    return {
        "access_token": access_token,
        "refresh_token": token.get("refreshToken") or "",
        "expires_at": token.get("expiresAt") or "",
        "refresh_expires_at": token.get("refreshExpiresAt") or "",
        "token_type": token.get("tokenType") or "Bearer",
        "scope": token.get("scope") or "",
        "domain": token.get("domain") or "",
        "user_id": uid,
        "nickname": nickname,
        "enterprise_id": account.get("enterpriseId") or "",
        "account_type": account.get("accountType") or "personal",
    }


# ── 请求头（buddy.ts / buddy-adapter.ts 的 send） ───────────────────────────

def credential_request_headers(credential: dict) -> dict[str, str]:
    """凭据级基础头（``X-Domain`` 空串必回退默认域名）。"""
    headers: dict[str, str] = {
        HTTP_HEADER_DOMAIN: (credential.get("domain") or "") or API_DOMAIN,
        "User-Agent": BUDDY_USER_AGENT,
    }
    enterprise = credential.get("enterprise_id") or ""
    if enterprise != "":
        headers[HTTP_HEADER_ENTERPRISE_ID] = enterprise
        headers[HTTP_HEADER_TENANT_ID] = enterprise
    return headers


def credential_auth_headers(credential: dict) -> dict[str, str]:
    return {**credential_request_headers(credential),
            "Authorization": f"Bearer {credential.get('access_token') or ''}"}


def resolve_user_agent(model: str) -> str:
    """中国版只有一条产品线，无需按模型分档（product.ts 的 userAgentByModelFamily 为空）。"""
    return BUDDY_USER_AGENT


def models_headers(credential: dict) -> dict[str, str]:
    """模型目录请求头：凭据级基础头 + 按产品覆盖域名/UA + 部署类型与产品码。"""
    return {
        **credential_auth_headers(credential),
        HTTP_HEADER_DOMAIN: API_DOMAIN,
        "User-Agent": BUDDY_USER_AGENT,
        HTTP_HEADER_PRODUCT: BUDDY_DEPLOYMENT_TYPE,
        HTTP_HEADER_PRODUCT_CODE: BUDDY_PRODUCT_CODE,
    }


def chat_headers(credential: dict, model: str) -> dict[str, str]:
    """chat 请求头（含用量归属头族；后台「使用端」列按这组头归因）。"""
    return {
        "Authorization": f"Bearer {credential.get('access_token') or ''}",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        # X-Domain 以产品配置为准（凭据里的 domain 是登录时站点的快照）。
        HTTP_HEADER_DOMAIN: API_DOMAIN or (credential.get("domain") or ""),
        HTTP_HEADER_PRODUCT_CODE: BUDDY_PRODUCT_CODE,
        "X-Agent-Purpose": "conversation",
        "X-IDE-Name": ATTRIBUTION_NAME,
        "X-IDE-Type": ATTRIBUTION_NAME,
        "X-IDE-Version": CLIENT_VERSION,
        HTTP_HEADER_PRODUCT: ATTRIBUTION_NAME,
        "User-Agent": resolve_user_agent(model),
    }


# ── 控制面请求 ─────────────────────────────────────────────────────────────

def response_code(body: Any) -> int:
    if not isinstance(body, dict):
        return 0
    code = body.get("code")
    if isinstance(code, bool):
        return 0
    if isinstance(code, int):
        return code
    if isinstance(code, float) and math.isfinite(code):
        return int(code)
    return 0


def response_message(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    message = body.get("message")
    return message if isinstance(message, str) else ""


def response_data(body: Any) -> Any:
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    return None if data is None else data


async def _request(method: str, url: str, headers: dict[str, str], *, timeout_s: float) -> tuple[int, Any]:
    """发起一次 CodeBuddy 控制面请求，返回 (status, body)；网络失败抛 UpstreamError。"""
    client = await get_client()
    try:
        response = await client.request(method, url, headers=headers, timeout=timeout_s)
    except httpx.HTTPError as error:
        reason = str(error) or error.__class__.__name__
        raise UpstreamError(f"buddy: {method} {url} network error: {reason}", CODE["transport"])
    try:
        body: Any = response.json()
    except ValueError:
        body = None
    return response.status_code, body


async def fetch_auth_state() -> dict:
    """``POST /v2/plugin/auth/state?platform=ide`` → ``{state, authUrl}``（无需认证）。"""
    url = f"{API_ENDPOINT}{AUTH_STATE_PATH}?platform={PLATFORM}"
    headers = {
        HTTP_HEADER_DOMAIN: API_DOMAIN,
        HTTP_HEADER_NO_AUTHORIZATION: "true",
        HTTP_HEADER_NO_USER_ID: "true",
        HTTP_HEADER_NO_ENTERPRISE_ID: "true",
        HTTP_HEADER_NO_DEPARTMENT_INFO: "true",
        "User-Agent": BUDDY_USER_AGENT,
    }
    status, body = await _request("POST", url, headers, timeout_s=STATE_REQUEST_TIMEOUT_S)
    if status != 200:
        raise UpstreamError(f"buddy: auth/state HTTP {status}: {response_message(body)}", CODE["server"], status=status)
    data = response_data(body)
    if not isinstance(data, dict):
        raise UpstreamError(f"buddy: auth/state 响应缺少 data 字段: {json.dumps(body, ensure_ascii=False)[:200]}",
                            CODE["server"])
    state = data.get("state") if isinstance(data.get("state"), str) else ""
    auth_url = data.get("authUrl") if isinstance(data.get("authUrl"), str) else ""
    if state == "":
        raise UpstreamError("buddy: auth/state 响应缺少 state 字段", CODE["server"])
    if auth_url == "":
        raise UpstreamError("buddy: auth/state 响应缺少 authUrl 字段", CODE["server"])
    return {"state": state, "authUrl": auth_url}


async def loop_get_token(state: str, *, timeout_s: float = LOGIN_TIMEOUT_S,
                         poll_interval_s: float = POLL_INTERVAL_S) -> dict:
    """``GET /v2/plugin/auth/token?state=...`` 轮询取令牌（11217 = 继续轮询）。"""
    url = f"{API_ENDPOINT}{AUTH_TOKEN_PATH}?state={_quote(state)}"
    headers = {HTTP_HEADER_NO_AUTHORIZATION: "true", "User-Agent": BUDDY_USER_AGENT}
    deadline = time.monotonic() + timeout_s
    while True:
        if time.monotonic() >= deadline:
            raise UpstreamError("buddy: 获取 token 超时（5 分钟）", CODE["timeout"])
        await asyncio.sleep(poll_interval_s)
        try:
            status, body = await _request("GET", url, headers, timeout_s=REQUEST_TIMEOUT_S)
        except UpstreamError:
            # 网络错误：继续轮询（不中断登录流程）。
            continue
        if status == 200:
            data = response_data(body)
            if data is not None:
                return parse_token_data(data)
            continue
        if response_code(body) == CODE_TOKEN_NOT_READY:
            continue
        raise UpstreamError(f"buddy: auth/token HTTP {status} code={response_code(body)}: {response_message(body)}",
                            CODE["server"], status=status)


async def get_account(state: str, token: dict, *, timeout_s: float = LOGIN_TIMEOUT_S,
                      poll_interval_s: float = POLL_INTERVAL_S) -> dict:
    """``GET /v2/plugin/login/account?state=...`` 轮询取账户信息（12151 = 继续轮询）。"""
    url = f"{API_ENDPOINT}{LOGIN_ACCOUNT_PATH}?state={_quote(state)}"
    # 登录流程里服务端**本次刚下发**的 token.domain 是权威值，仅空串时回退产品域名。
    headers = {
        HTTP_HEADER_DOMAIN: (token.get("domain") or "") or API_DOMAIN,
        "Authorization": f"Bearer {token.get('accessToken') or ''}",
        HTTP_HEADER_NO_USER_ID: "true",
        HTTP_HEADER_NO_ENTERPRISE_ID: "true",
        "User-Agent": BUDDY_USER_AGENT,
    }
    deadline = time.monotonic() + timeout_s
    while True:
        if time.monotonic() >= deadline:
            raise UpstreamError("buddy: 获取账户信息超时（5 分钟）", CODE["timeout"])
        await asyncio.sleep(poll_interval_s)
        try:
            status, body = await _request("GET", url, headers, timeout_s=REQUEST_TIMEOUT_S)
        except UpstreamError:
            continue
        if status == 200:
            data = response_data(body)
            if data is not None:
                return parse_account_data(data)
            continue
        if response_code(body) == CODE_ACCOUNT_NOT_READY:
            continue
        raise UpstreamError(f"buddy: login/account HTTP {status} code={response_code(body)}: {response_message(body)}",
                            CODE["server"], status=status)


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(str(value), safe="")


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


# ── 登录（buddy-oauth.ts 的 runBuddyLoginFlow） ─────────────────────────────

async def run_login(*, open_browser: bool = True, timeout_s: float = LOGIN_TIMEOUT_S,
                    poll_interval_s: float = POLL_INTERVAL_S) -> dict:
    """完整登录：fetchAuthState → 打开浏览器 → 轮询 token → 轮询 account。

    注意：CodeBuddy（``appendSessionParams: false``）的 authUrl **原样使用**，
    不追加 ``version`` / ``loginSessionId``（那是 WorkBuddy 国际版的行为）。
    """
    auth = await fetch_auth_state()
    if open_browser:
        _open_external(auth["authUrl"])
    token = await loop_get_token(auth["state"], timeout_s=timeout_s, poll_interval_s=poll_interval_s)
    account = await get_account(auth["state"], token, timeout_s=timeout_s, poll_interval_s=poll_interval_s)
    credential = build_credential(token, account)
    credential["login_url"] = auth["authUrl"]
    return credential


# ── 续期（buddy-oauth.ts 的 refreshToken + buddy-auth.ts 的字段合并） ───────

async def refresh_credential(credential: dict) -> dict:
    """``POST /v2/plugin/auth/token/refresh``：用 ``X-Refresh-Token`` 头换新令牌。"""
    if not is_refreshable(credential):
        raise UpstreamError("buddy: 无 refresh_token，请重新登录", CODE["credential"])
    url = f"{API_ENDPOINT}{AUTH_REFRESH_PATH}"
    headers = {
        **credential_request_headers(credential),
        HTTP_HEADER_DOMAIN: API_DOMAIN,
        "User-Agent": BUDDY_USER_AGENT,
        "Authorization": f"Bearer {credential.get('access_token') or ''}",
        HTTP_HEADER_REFRESH_TOKEN: credential.get("refresh_token") or "",
        HTTP_HEADER_AUTH_REFRESH_SOURCE: AUTH_REFRESH_SOURCE,
    }
    status, body = await _request("POST", url, headers, timeout_s=REQUEST_TIMEOUT_S)
    if status != 200:
        code = response_code(body)
        message = response_message(body)
        expired = (status in (401, 403) or code in (401, 403)
                   or "expired" in message or "invalid" in message)
        raise UpstreamError(f"buddy: 刷新 token HTTP {status} code={code}: {message}",
                            CODE["credential"] if expired else CODE["server"], status=status)
    data = response_data(body)
    if data is None:
        raise UpstreamError("buddy: 刷新 token 响应缺少 data 字段", CODE["server"], status=status)
    token = parse_token_data(data)
    merged = dict(credential)
    merged.update({
        "access_token": token["accessToken"],
        "refresh_token": token["refreshToken"],
        "expires_at": token["expiresAt"],
        "refresh_expires_at": token["refreshExpiresAt"],
        "token_type": token["tokenType"],
        "scope": token["scope"],
    })
    if token["domain"]:
        merged["domain"] = token["domain"]
    return merged


# ── 模型目录（buddy-oauth.ts 的 fetchModels + buddy.ts 的 parseModelsFromConfig） ──

def display_name_for_model(model_id: str) -> str:
    return MODEL_DISPLAY_NAMES.get(model_id, model_id)


def is_auto_select_alias(model_id: str) -> bool:
    """``auto`` / ``default`` 是自动选择别名，不是真实模型。"""
    return model_id in ("auto", "default")


def is_chat_model(model_id: str, meta: dict | None) -> bool:
    """过滤补全/NES 专用模型、输出上限过小的模型与 ``text-to-image`` 生成模型。"""
    if model_id.startswith("nes-") or model_id.startswith("completion-") or model_id.startswith("codewise-"):
        return False
    if isinstance(meta, dict) and meta.get("supportsExtra") is True:
        return False
    max_output = (meta or {}).get("maxOutputTokens")
    if isinstance(max_output, (int, float)) and not isinstance(max_output, bool) and 0 < max_output <= 256:
        return False
    tags = (meta or {}).get("tags")
    if isinstance(tags, list) and any(tag == "text-to-image" for tag in tags):
        return False
    return True


def parse_model_meta(record: dict | None) -> dict:
    """远端**显式**下发的元数据（缺失即缺省，不猜默认值）。"""
    if not isinstance(record, dict):
        return {}
    meta: dict[str, Any] = {}
    limit = record.get("maxInputTokens")
    if isinstance(limit, (int, float)) and not isinstance(limit, bool) and math.isfinite(limit) and limit > 0:
        meta["contextWindow"] = int(limit)
    max_output = record.get("maxOutputTokens")
    if isinstance(max_output, (int, float)) and not isinstance(max_output, bool) and math.isfinite(max_output) and max_output > 0:
        meta["maxOutput"] = int(max_output)
    if isinstance(record.get("supportsImages"), bool):
        meta["vision"] = record["supportsImages"]
        meta["supportsImages"] = record["supportsImages"]
    reasoning = record.get("reasoning")
    if isinstance(reasoning, dict):
        efforts = reasoning.get("supportedEfforts")
        if isinstance(efforts, list):
            kept = [effort for effort in efforts if isinstance(effort, str) and effort != ""]
            if kept:
                meta["reasoningEfforts"] = kept
                meta["reasoning"] = True
        default_effort = reasoning.get("defaultEffort")
        if isinstance(default_effort, str) and default_effort != "":
            meta["defaultReasoningEffort"] = default_effort
    return meta


def _trial_model_ids(data: dict) -> list[str]:
    features = data.get("productFeaturesConfig")
    if not isinstance(features, dict):
        return []
    banner = features.get("ModelTrialBanner")
    if not isinstance(banner, dict):
        return []
    banners = banner.get("banners")
    if not isinstance(banners, list):
        return []
    ids: list[str] = []
    for item in banners:
        if isinstance(item, dict):
            target = item.get("targetModelId")
            if isinstance(target, str) and target != "":
                ids.append(target)
    return ids


def parse_models_from_config(body: Any) -> list[dict]:
    """解析 ``GET /v3/config``（``data.models`` / ``data.agents``）为模型列表。"""
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    if not isinstance(data, dict):
        return []
    meta_by_id: dict[str, dict] = {}
    raw_models = data.get("models")
    if isinstance(raw_models, list):
        for model in raw_models:
            if isinstance(model, dict) and isinstance(model.get("id"), str):
                meta_by_id[model["id"]] = model
    agent_referenced: set[str] = set()
    agents = data.get("agents")
    if isinstance(agents, list):
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            models = agent.get("models")
            if isinstance(models, list):
                for model in models:
                    if isinstance(model, str):
                        agent_referenced.add(model)

    parsed: list[dict] = []
    seen: set[str] = set()

    def push(model_id: str, *, referenced: bool | None = None) -> None:
        if is_auto_select_alias(model_id) or model_id in seen or not is_chat_model(model_id, meta_by_id.get(model_id)):
            return
        seen.add(model_id)
        meta = meta_by_id.get(model_id)
        remote_name = meta.get("name") if isinstance(meta, dict) and isinstance(meta.get("name"), str) else ""
        entry: dict[str, Any] = {
            "id": model_id,
            "name": remote_name if remote_name else display_name_for_model(model_id),
        }
        entry.update(parse_model_meta(meta))
        entry["reasoning"] = bool(entry.get("reasoning"))
        if referenced is True or model_id in agent_referenced:
            entry["agentReferenced"] = True
        parsed.append(entry)

    # 1. 主对话 agent 引用的模型优先（企业端点用 `cli`，/v3/config 用 `craft`）。
    if isinstance(agents, list):
        for agent_name in PREFERRED_AGENT_NAMES:
            found = False
            for agent in agents:
                if not isinstance(agent, dict) or agent.get("name") != agent_name:
                    continue
                models = agent.get("models")
                if isinstance(models, list):
                    for model in models:
                        if isinstance(model, str):
                            push(model)
                found = True
                break
            if found:
                break
    # 2. 补齐 data.models 里其余可对话模型。
    for model_id in meta_by_id:
        push(model_id)
    # 3. 追加试用模型（试用横幅本身就是「服务端推荐可用」的信号）。
    for model_id in _trial_model_ids(data):
        if not is_auto_select_alias(model_id) and model_id not in seen:
            seen.add(model_id)
            entry: dict[str, Any] = {"id": model_id, "name": display_name_for_model(model_id)}
            entry.update(parse_model_meta(meta_by_id.get(model_id)))
            entry["reasoning"] = bool(entry.get("reasoning"))
            entry["agentReferenced"] = True
            parsed.append(entry)
    return parsed


def merge_remote_models(primary: list[dict], extra: list[dict]) -> list[dict]:
    """按 id 合并两个端点的模型列表（同 id 以 ``primary`` 为准，extra 追加在后）。"""
    known = {model.get("id") for model in primary}
    return [*primary, *[model for model in extra if model.get("id") not in known]]


async def _request_scoped_models(headers: dict[str, str]) -> list[dict] | None:
    """企业模型端点（个人账号用字面量 ``personal``）；不可用时返回 None 交上层回退。"""
    url = f"{API_ENDPOINT}/console/enterprises/{ENTERPRISE_MODELS_SCOPE}/models"
    try:
        status, body = await _request("GET", url, headers, timeout_s=REQUEST_TIMEOUT_S)
    except UpstreamError:
        return None
    if status != 200:
        return None
    models = parse_models_from_config(body)
    return models if models else None


async def _request_config(headers: dict[str, str]) -> list[dict]:
    """``GET /v3/config``；任何失败都返回空列表（它只是增强）。"""
    try:
        status, body = await _request("GET", f"{API_ENDPOINT}{CONFIG_PATH}", headers, timeout_s=REQUEST_TIMEOUT_S)
    except UpstreamError:
        return []
    if status != 200:
        return []
    return parse_models_from_config(body)


def fallback_catalog() -> list[dict]:
    """内置兜底表（``product.ts`` 的 CODEBUDDY_FALLBACK_MODELS）。"""
    return [dict(model) for model in FALLBACK_MODELS]


async def fetch_models(credential: dict) -> dict:
    """三层回退拉取模型目录；**任何失败都不抛错**，最差返回内置兜底表。"""
    models: list[dict] = []
    try:
        if not isinstance(credential, dict) or not credential.get("access_token"):
            raise UpstreamError("buddy: 凭据缺少 access_token", CODE["credential"])
        headers = models_headers(credential)
        scoped = await _request_scoped_models(headers)
        if scoped is not None:
            models = merge_remote_models(scoped, await _request_config(headers))
        else:
            models = await _request_config(headers)
    except Exception:  # noqa: BLE001
        models = []
    if not models:
        return {"models": fallback_catalog(), "fallback": True}
    for model in models:
        if model.get("contextWindow") is None:
            window = CONTEXT_WINDOWS.get(str(model.get("id")))
            if window is not None:
                model["contextWindow"] = window
        if "vision" not in model and str(model.get("id")) in IMAGE_MODELS:
            model["vision"] = True
    return {"models": models, "at": int(time.time() * 1000)}


# ── 推理（buddy-adapter.ts 的 stream） ─────────────────────────────────────

def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, float) and math.isfinite(value) and value > 0 and value.is_integer():
        return int(value)
    return None


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "".join(str(block.get("text") or "") for block in content
                   if isinstance(block, dict) and block.get("type") == "text")


def serialize_messages(messages: Any) -> list[dict]:
    """把 OpenAI 形状消息序列化为 CodeBuddy 传输格式。

    assistant 消息**始终**携带 ``reasoning_content``（推理模型缺失会 400）；
    正文为空且带 ``tool_calls`` 时 ``content`` 必须为 ``null``。
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
        text = content if isinstance(content, str) else _content_to_text(content)
        tool_calls = message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else []
        reasoning = message.get("reasoning_content")
        entry: dict[str, Any] = {
            "role": "assistant",
            "content": None if (text == "" and tool_calls) else text,
            "reasoning_content": reasoning if isinstance(reasoning, str) else "",
        }
        if tool_calls:
            entry["tool_calls"] = tool_calls
        wire.append(entry)
    return wire


def _catalog_model(catalog: Any, model_id: str) -> dict | None:
    if not isinstance(catalog, dict):
        return None
    for model in catalog.get("models") or []:
        if isinstance(model, dict) and model.get("id") == model_id:
            return model
    return None


def efforts_for(model_id: str, catalog: Any) -> list[str]:
    """可枚举思考等级：远端 → 产品兜底表 → 适配器静态表。"""
    remote = _catalog_model(catalog, model_id) or {}
    efforts = remote.get("reasoningEfforts")
    if isinstance(efforts, list) and efforts:
        return [effort for effort in efforts if isinstance(effort, str) and effort != ""]
    fallback = FALLBACK_INDEX.get(model_id) or {}
    efforts = fallback.get("reasoningEfforts")
    if isinstance(efforts, list) and efforts:
        return [effort for effort in efforts if isinstance(effort, str) and effort != ""]
    return list(ADAPTER_REASONING_EFFORTS.get(model_id) or [])


def default_effort_for(model_id: str, catalog: Any) -> str | None:
    remote = _catalog_model(catalog, model_id) or {}
    declared = remote.get("defaultReasoningEffort") or (FALLBACK_INDEX.get(model_id) or {}).get("defaultReasoningEffort")
    if isinstance(declared, str) and declared in efforts_for(model_id, catalog):
        return declared
    return None


def max_tokens_for(model_id: str, body: dict, catalog: Any) -> int | None:
    explicit = _positive_int(body.get("max_tokens"))
    if explicit is not None:
        return explicit
    remote = _catalog_model(catalog, model_id) or {}
    remote_max = _positive_int(remote.get("maxOutput") or remote.get("maxOutputTokens"))
    if remote_max is not None:
        return remote_max
    return _positive_int((FALLBACK_INDEX.get(model_id) or {}).get("maxOutput"))


def build_payload(body: dict, model_id: str, catalog: Any) -> dict:
    """构造上游请求体（字段名与 buddy-adapter.ts 的 ``bodyObj`` 一致）。"""
    session = body.get("prompt_cache_key") or body.get("user") or body.get("conversation")
    prompt_cache_key = str(session) if isinstance(session, str) and session != "" else _SESSION_ID
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": serialize_messages(body.get("messages")),
        "stream": True,
        # prompt_cache_key 让服务端启用前缀缓存并在 usage 中返回缓存命中。
        "prompt_cache_key": prompt_cache_key,
    }
    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        payload["tools"] = tools
    temperature = body.get("temperature")
    if isinstance(temperature, (int, float)) and not isinstance(temperature, bool):
        payload["temperature"] = temperature
    stop = body.get("stop")
    if isinstance(stop, list) and stop:
        payload["stop"] = stop
    max_tokens = max_tokens_for(model_id, body, catalog)
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    # DeepSeek 系：thinking 字段单独不生效，reasoning_effort 才是真正的开关。
    deepseek = model_id.strip().lower().startswith("deepseek")
    if deepseek:
        payload["thinking"] = {"type": "enabled"}
    efforts = efforts_for(model_id, catalog)
    requested = body.get("reasoning_effort")
    if isinstance(requested, str) and requested in efforts:
        payload["reasoning_effort"] = requested
    elif deepseek and efforts:
        payload["reasoning_effort"] = default_effort_for(model_id, catalog) or ("high" if "high" in efforts else efforts[0])
    return payload


_REJECTION_CODE = re.compile(r'"code"\s*:\s*11140')
_REJECTION_ILLEGAL = re.compile(r"request illegal", re.IGNORECASE)
_REJECTION_SAFETY = re.compile(r"安全审核|safety review", re.IGNORECASE)


def is_content_rejection(payload_text: str) -> bool:
    """安全策略拦截（业务码 11140 / ``request illegal`` / 安全审核措辞）。"""
    if payload_text == "":
        return False
    return bool(_REJECTION_CODE.search(payload_text) or _REJECTION_ILLEGAL.search(payload_text)
                or _REJECTION_SAFETY.search(payload_text))


def _error_code(status: int) -> str:
    if status in (401, 403):
        return CODE["credential"]
    if status == 429:
        return CODE["quota"]
    if status >= 500:
        return CODE["server"]
    return CODE["client"]


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """POST 一轮 chat/completions 并以内部 chunk 产出（SSE 由 ``read_stream`` 投影）。"""
    model_id = str(body.get("model") or "")
    payload = build_payload(body, model_id, catalog)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    url = f"{API_ENDPOINT}{CHAT_PATH}"

    channel = create_channel()
    client = await get_client()

    def forward(payload_text: str) -> None:
        """送入内部流；流内安全策略拦截（HTTP 200 + 内嵌 11140 帧）如实报错。"""
        if is_content_rejection(payload_text):
            parsed: Any = None
            try:
                parsed = json.loads(payload_text)
            except ValueError:
                parsed = None
            # 判据必须窄：有效内容帧一定带 choices。
            if isinstance(parsed, dict) and parsed.get("choices") is None:
                raise UpstreamError(
                    "buddy: 当前账号被服务端安全策略拦截（HTTP 200，流内错误帧下发）。"
                    f"该拦截按账号生效，请更换账号后重试：{payload_text[:200]}",
                    CODE["client"], status=200)
        channel.push(payload_text)

    async def produce() -> None:
        try:
            nonlocal credential
            response = await client.send(
                client.build_request("POST", url, headers=chat_headers(credential, model_id), content=data),
                stream=True)
            if response.status_code in (401, 403):
                await response.aread()
                refreshed = await refresh_credential(credential)
                credential = refreshed
                if on_refresh is not None:
                    on_refresh(refreshed)
                response = await client.send(
                    client.build_request("POST", url, headers=chat_headers(credential, model_id), content=data),
                    stream=True)
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                raise UpstreamError(f"buddy: HTTP {response.status_code} {text[:200]}",
                                    _error_code(response.status_code), status=response.status_code)
            head = await read_head(response.aiter_bytes(), 4096, STREAM_TIMEOUT_S)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("buddy: empty model response body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), forward, STREAM_TIMEOUT_S)
            else:
                text = (await _read_remainder(head)).decode("utf-8", "replace")
                try:
                    parsed = json.loads(text)
                except ValueError:
                    raise UpstreamError("buddy: unexpected non-stream response", CODE["server"])
                if isinstance(parsed, dict) and parsed.get("error"):
                    message = parsed["error"]
                    message = message.get("message") if isinstance(message, dict) else message
                    raise UpstreamError(f"buddy: {message or 'unknown error'}", CODE["server"])
                channel.push(json.dumps(parsed, ensure_ascii=False))
            channel.push(None)
        except BaseException as error:  # noqa: BLE001
            channel.push(error if isinstance(error, BaseException) else RuntimeError(str(error)))

    task = asyncio.create_task(produce())
    reader = read_stream(channel.read(), "chat", None, None)
    try:
        while True:
            done, value = await reader.next()
            if done:
                return
            yield value
    finally:
        await reader.close()
        if not task.done():
            task.cancel()
        try:
            await task
        except BaseException:  # noqa: BLE001
            pass
