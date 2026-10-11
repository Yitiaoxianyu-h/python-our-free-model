"""TRAE（字节跳动 TRAE IDE / SOLO）渠道。

移植自原版 channel-pack 的 ``trae.ts`` / ``trae-oauth.ts`` / ``trae-auth.ts`` /
``trae-adapter.ts`` / ``trae-errors.ts`` / ``trae-product.ts``。

## 协议速览（trae.ts 的表格）

| 用途 | 方法 | 路径 | Host | 认证 |
|------|------|------|------|------|
| 对话 | POST | ``/api/agent/v3/llm_utils_chat`` | trae-api-cn.mchost.guru | ``Cloud-IDE-JWT`` |
| 模型列表 | POST | ``/api/ide/v1/batch_get_detail_param`` | (同上) | ``Cloud-IDE-JWT`` |
| 换 token | POST | ``/cloudide/api/v3/trae/oauth/ExchangeToken`` | api.trae.com.cn | 无（用 refreshToken） |
| 用户信息 | POST | ``/cloudide/api/v3/trae/GetUserInfo`` | (同上) | ``Cloud-IDE-JWT`` |

## 与其它渠道的关键差异（逐条来自 TS 注释）

1. **登录是「本地回调 + 直传 token」**：TRAE 授权页强制回调
   ``http://127.0.0.1:18080/authorize``，回调**直接回传** ``refreshToken`` /
   ``userInfo`` / ``userJwt``（不是 OAuth 的 ``?code=``）；参数名必须是
   ``auth_callback_url``（17 参数一个都不能少）。拿到 refreshToken 后走
   ``ExchangeToken`` 换 accessToken，并**轮换 refreshToken**（续期后必须回写）。
2. **凭据带机器指纹**：``machine_id`` / ``device_id`` 都是 32 位 hex，登录时生成
   并持久化；每次对话请求都要带（``X-Machine-Id`` / ``X-Device-Id``）。
3. **载荷必须转换**：OpenAI 的 ``{model, messages, tools, tool_choice}`` 要映射成
   SOLO 形状（``function`` / ``config_name`` / ``messages[].content`` 数组化 /
   ``tools[].function.parameters`` 序列化成 JSON 字符串）。
4. **SSE 是自定义格式**（非 OpenAI 标准）：``event:`` 行 + ``data:`` 行成对出现，
   事件名是 ``metadata`` / ``timing_cost`` / ``output`` / ``extra_info`` /
   ``token_usage`` / ``done`` / ``error``，故本模块**自己解析**，不套
   ``read_stream`` 的 chat 线。

## 相对 TS 的有意省略（不编造替代实现）

- 思考死循环守卫、纯空白思考压制、think 标签收尾切分、``course`` 泄漏清洗：
  这些是 DSH 侧的 QoL 补丁，与本渠道的线协议无关，本移植不引入。
- 活动折扣解析（``readActivityDiscount``）：只保留消耗倍率（``consumptionRate``）。
- 多账号轮换 / 限流标记 / 机器指纹轮换默认关闭（TS 默认值一致：不轮换）。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import secrets
import time
from typing import Any, AsyncIterator, Callable

import httpx

from ..http_client import CODE, UpstreamError, get_client, read_head, _read_remainder, _replay, sniff_body

CHANNEL_ID = "trae"

# ── 端点（trae.ts 的路径常量） ───────────────────────────────────────────────

TRAE_CHAT_PATH = "/api/agent/v3/llm_utils_chat"
TRAE_MODELS_PATH = "/api/ide/v1/get_detail_param"
TRAE_BATCH_MODELS_PATH = "/api/ide/v1/batch_get_detail_param"
TRAE_EXCHANGE_PATH = "/cloudide/api/v3/trae/oauth/ExchangeToken"
TRAE_USER_INFO_PATH = "/cloudide/api/v3/trae/GetUserInfo"
TRAE_CHECKIN_STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
TRAE_CHECKIN_CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
TRAE_ENT_USAGE_PATH = "/trae/api/v2/pay/ide_user_ent_usage"
TRAE_CALLBACK_PATH = "/authorize"

#: 控制面请求超时（秒）；对话流式请求另有超时。
TRAE_REQUEST_TIMEOUT_S = 30.0
#: 登录流程总超时（秒，对齐 Go 端 10 分钟）。
TRAE_LOGIN_TIMEOUT_S = 10 * 60
#: 对话流读取超时（秒）。
TRAE_STREAM_TIMEOUT_S = 600.0
#: 回调首选端口（TRAE 登录页强制回传 127.0.0.1:18080）。
TRAE_CALLBACK_PORT = 18080

# ── 产品配置（trae-product.ts 的 TRAE） ─────────────────────────────────────

TRAE_AGENT_HOST = "https://trae-api-cn.mchost.guru"
TRAE_UG_HOST = "https://api.trae.cn"
TRAE_OAUTH_HOST = "https://api.trae.com.cn"
TRAE_CONSOLE_HOST = "https://www.trae.cn"

CLIENT_ID = "en1oxy7wnw8j9n"
APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
IDE_VERSION = "0.1.52"
IDE_VERSION_CODE = "20260811"
DEVICE_BRAND = "Apple"
OS_VERSION = "macOS 15.7.4"
FUNCTION = "solo_work_lite"
FALLBACK_MAX_OUTPUT_TOKENS = 32_000
PLUGIN_VERSION = "2.3.62834"
USER_AGENT = "Trae/0.1.52"
DEFAULT_MODEL = "glm-5.2"

#: 签到/积分头族里用到的固定值（trae.ts 的 ``Package-Type`` / ``X-Lscbd-Aid``）。
PACKAGE_TYPE = "stable_cn"
LSCBD_AID = "787976"

#: 单次请求输出额度的安全上限（trae.ts 的 ``TRAE_DEFAULT_MAX_COMPLETION_TOKENS``）。
TRAE_DEFAULT_MAX_COMPLETION_TOKENS = 64_000

#: Max 模式（1M 上下文）三件套常量。
TRAE_MAX_CONTEXT_TOKENS = 1_000_000
TRAE_MAX_PROMPT_TOKENS = 936_000
TRAE_MAX_OUTPUT_TOKENS = 64_000
TRAE_MAX_MODE_TYPE = 1

#: 白名单外（必然调不通）的通道整组丢弃 —— trae-product.ts 的 ``TRAE_CHANNELS``。
DEFAULT_CHANNELS: list[str] = [
    # 通用通道（顺序即优先级）
    "solo_agent", "solo_work_lite", "solo_agent_remote", "solo_work_remote", "solo_agent_lite",
    # 专用通道
    "chat_v3", "builder_v3", "solo_coder", "solo_design_lite", "solo_design_remote",
    "git_ai", "code_reviewer", "code_review_summary", "multimodal", "system_diagnosis",
]

#: ``batch_get_detail_param`` 要传的**全部 22 个 function**（真实 CN IDE 的做法）。
BATCH_FUNCTIONS: list[str] = [
    "ui_builder_v2", "solo_coder", "chat_v3", "solo_builder",
    "builder_v3", "builder", "chat", "inline_chat", "git_ai",
    "custom_agent_generation", "utils", "code_reviewer",
    "code_review_summary", "solo_agent", "solo_agent_remote",
    "solo_work_remote", "solo_agent_lite", "solo_work_lite",
    "solo_design_lite", "solo_design_remote", "multimodal",
    "system_diagnosis",
]

#: 兜底模型目录（32 个，对齐 trae-product.ts 的 ``TRAE_FALLBACK_MODELS``）。
FALLBACK_MODELS: list[dict] = [
    {"id": "DeepSeek-V4-Flash-Official", "name": "DeepSeek V4 Flash Official", "contextWindow": 200_000},
    {"id": "Doubao-Seed-2.1-Pro", "name": "Doubao Seed 2.1 Pro", "contextWindow": 200_000},
    {"id": "seed-code-pro-0430", "name": "Seed Code Pro 0430", "contextWindow": 200_000},
    {"id": "Doubao-Seed-2.1-Turbo", "name": "Doubao Seed 2.1 Turbo", "contextWindow": 200_000},
    {"id": "Doubao-Seed-2.0-Code", "name": "Doubao Seed 2.0 Code", "contextWindow": 200_000},
    {"id": "browser_use_subagent", "name": "Browser Use Subagent", "contextWindow": 200_000, "isHidden": True},
    {"id": "glm-5.2", "name": "GLM-5.2", "contextWindow": 200_000},
    {"id": "glm-5-turbo", "name": "GLM-5 Turbo", "contextWindow": 200_000},
    {"id": "glm-5", "name": "GLM-5", "contextWindow": 200_000},
    {"id": "DeepSeek-V4-Pro", "name": "DeepSeek V4 Pro", "contextWindow": 200_000},
    {"id": "DeepSeek-V4-Flash", "name": "DeepSeek V4 Flash", "contextWindow": 200_000},
    {"id": "kimi-k3", "name": "Kimi K3", "contextWindow": 200_000},
    {"id": "kimi-k2.7-code", "name": "Kimi K2.7 Code", "contextWindow": 200_000},
    {"id": "kimi-k2.6", "name": "Kimi K2.6", "contextWindow": 200_000},
    {"id": "minimax-m3", "name": "MiniMax M3", "contextWindow": 200_000},
    {"id": "qwen-3.7-plus", "name": "Qwen 3.7 Plus", "contextWindow": 200_000},
    {"id": "sagitta", "name": "Sagitta", "contextWindow": 200_000},
    {"id": "aquila", "name": "Aquila", "contextWindow": 200_000},
    {"id": "custom_model_gemini", "name": "Custom Gemini", "contextWindow": 200_000},
    {"id": "custom_model_placeholder", "name": "Custom Placeholder", "contextWindow": 200_000},
    {"id": "custom_model_1M_text", "name": "Custom 1M Text", "contextWindow": 200_000},
    {"id": "custom_model_1M", "name": "Custom 1M", "contextWindow": 200_000},
    {"id": "custom_model_kimi", "name": "Custom Kimi", "contextWindow": 200_000},
    {"id": "custom_model_claude", "name": "Custom Claude", "contextWindow": 200_000},
    {"id": "custom_model_gpt-5", "name": "Custom GPT-5", "contextWindow": 200_000},
    {"id": "custom_model_no-fc", "name": "Custom No-FC", "contextWindow": 200_000},
    {"id": "custom_model_deepseek_chat", "name": "Custom DeepSeek Chat", "contextWindow": 200_000},
    {"id": "custom_model_deepseek_reasoner", "name": "Custom DeepSeek Reasoner", "contextWindow": 200_000},
    {"id": "custom_model_deepseek_v4", "name": "Custom DeepSeek V4", "contextWindow": 200_000},
    {"id": "explore_sub_agent_v13", "name": "Explore Sub Agent V13", "contextWindow": 200_000, "isHidden": True},
    {"id": "explore_sub_agent_v2", "name": "Explore Sub Agent V2", "contextWindow": 200_000, "isHidden": True},
    {"id": "summary", "name": "Summary", "contextWindow": 200_000, "isHidden": True},
]

FALLBACK_INDEX: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS}
#: 渠道模块约定：``manager._context_for`` 读这个表做兜底窗口。
CONTEXT_WINDOWS: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS}

#: 推理档位 wire 值 → 展示名（trae-adapter.ts 的 ``TRAE_EFFORT_NAMES``，仅展示用）。
TRAE_EFFORT_NAMES: dict[str, str] = {
    "light": "Light", "minimal": "Minimal", "low": "Low", "medium": "Medium",
    "high": "High", "extra_high": "Extra High", "xhigh": "XHigh", "max": "Max",
}

#: 推理档位强度序（只用于挑默认档，不参与 wire 取值）。
REASONING_LADDER: list[str] = [
    "minimal", "light", "low", "medium", "high", "extra_high", "xhigh", "max",
]

#: 流内可换号错误码（trae-adapter.ts 的 ``isRotatableStreamError``）。
ROTATABLE_STREAM_CODES = (1005, 4008, 4011)

#: 已发起的 chat 请求计数（仅在启用机器指纹轮换时使用）。
_SEND_COUNT = 0


# ── 环境开关（trae-product.ts / trae-adapter.ts 的同名开关） ───────────────

def _env(*names: str) -> str | None:
    """按顺序取第一个非空环境变量（同时兼容 OFM_ / DSH_ 两套命名）。"""
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value
    return None


def resolve_channel_list() -> list[str]:
    """解析 ``OFM_TRAE_CHANNELS`` / ``DSH_TRAE_CHANNELS``；空/非法时回退默认表。"""
    raw = _env("OFM_TRAE_CHANNELS", "DSH_TRAE_CHANNELS")
    if raw is None:
        return list(DEFAULT_CHANNELS)
    parsed = [item.strip() for item in raw.split(",") if item.strip() != ""]
    return parsed if parsed else list(DEFAULT_CHANNELS)


def resolve_max_mode_flag() -> bool:
    """Max 模式（1M 上下文）开关，**默认开启**（与 trae-product.ts 一致）。"""
    raw = _env("OFM_TRAE_MAX_MODE", "DSH_TRAE_MAX_MODE")
    if raw is None:
        return True
    value = raw.strip().lower()
    return not (value in ("0", "false", "no", "off"))


def resolve_max_mode_models() -> list[str] | None:
    """Max 模式白名单；留空返回 ``None``（= 全部 ``max_mode`` 为真的模型都生效）。"""
    raw = _env("OFM_TRAE_MAX_MODELS", "DSH_TRAE_MAX_MODELS")
    if raw is None:
        return None
    parsed = [item.strip() for item in raw.split(",") if item.strip() != ""]
    return parsed if parsed else None


def resolve_rotate_machine_id() -> bool:
    """是否轮换机器指纹（**默认关闭**，与 trae-adapter.ts 的取舍一致）。"""
    return _env("OFM_TRAE_ROTATE_MACHINE_ID", "DSH_TRAE_ROTATE_MACHINE_ID") == "1"


def resolve_max_completion_tokens() -> int:
    """单次请求输出额度的安全上限（默认 64000；0 = 关闭收敛）。"""
    raw = _env("OFM_TRAE_MAX_COMPLETION_TOKENS", "DSH_TRAE_MAX_COMPLETION_TOKENS")
    if raw is not None:
        try:
            value = int(raw.strip())
        except ValueError:
            value = -1
        if value >= 0:
            return value
    return TRAE_DEFAULT_MAX_COMPLETION_TOKENS


def clamp_trae_max_tokens(value: Any, limit: int | None = None) -> int | None:
    """把输出额度收敛到安全上限；``None`` / 非法值原样返回（不编造数值）。"""
    ceiling = resolve_max_completion_tokens() if limit is None else limit
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    number = int(value)
    if number <= 0:
        return number
    if ceiling <= 0:
        return number
    return min(number, ceiling)


# ── JSON 安全读取（trae.ts 的 readStringField / readNumberField / readBooleanField） ──

_NUMBER_TEXT = re.compile(r"^-?\d+(\.\d+)?$")
_CJK = re.compile(r"[\u4e00-\u9fff]")


def read_string_field(source: Any, key: str) -> str:
    if not isinstance(source, dict):
        return ""
    value = source.get(key)
    if isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return str(value)
    return ""


def read_number_field(source: Any, key: str) -> float | None:
    if not isinstance(source, dict):
        return None
    value = source.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    if isinstance(value, str) and _NUMBER_TEXT.match(value.strip()):
        return float(value.strip())
    return None


def read_boolean_field(source: Any, key: str) -> bool | None:
    """只有**明确**的布尔语义才返回值（缺失返回 ``None``：上游没说）。"""
    if not isinstance(source, dict):
        return None
    value = source.get(key)
    if isinstance(value, bool):
        return value
    if value == 1 or value == "true":
        return True
    if value == 0 or value == "false":
        return False
    return None


def _json_object(raw: Any) -> dict | None:
    """宽松解析 JSON 对象字符串；非对象返回 ``None``。"""
    if not isinstance(raw, str) or raw == "":
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


# ── 过期时间与可刷新判定（trae.ts 的 traeCredentialExpiresAtMs / isTraeExpired） ──

def _jwt_payload(token: Any) -> dict | None:
    """只做 base64url 解码、不验签。"""
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


def credential_expires_at_ms(credential: dict) -> int | None:
    """兼容毫秒 / 秒 / ISO 三种形态；为空时回退 ``access_token`` 的 JWT ``exp``。"""
    raw = credential.get("expires_at")
    if isinstance(raw, str) and raw != "":
        if raw.isdigit():
            value = int(raw)
            return value if value > 1_000_000_000_000 else value * 1000
        try:
            from email.utils import parsedate_to_datetime

            parsed = parsedate_to_datetime(raw)
            if parsed is not None:
                return int(parsed.timestamp() * 1000)
        except Exception:  # noqa: BLE001
            pass
        try:
            from datetime import datetime

            iso = raw.replace("Z", "+00:00")
            return int(datetime.fromisoformat(iso).timestamp() * 1000)
        except Exception:  # noqa: BLE001
            pass
    return jwt_expires_at_ms(credential.get("access_token"))


def is_expired(credential: dict) -> bool:
    """无法解析过期时间时**不**判定过期（与 TS 同）。"""
    expires_at = credential_expires_at_ms(credential)
    return False if expires_at is None else int(time.time() * 1000) >= expires_at


def is_refreshable(credential: dict) -> bool:
    token = credential.get("refresh_token")
    return isinstance(token, str) and token != ""


# ── 身份 ID（登录时生成并持久化） ─────────────────────────────────────────

def generate_machine_id() -> str:
    """32 位 hex 机器指纹（16 字节 → 32 hex）。"""
    return secrets.token_hex(16)


def generate_device_id() -> str:
    """32 位 hex 设备号（``openssl rand -hex 16`` 的等价物）。"""
    return secrets.token_hex(16)


def derive_checkin_device_id(base_device_id: str, generation: int) -> str:
    """命中 9074 时派生新的签到设备号（sha256 前 32 位 hex）。"""
    if generation <= 0:
        return base_device_id
    return hashlib.sha256(f"{base_device_id}#gen{int(generation)}".encode("utf-8")).hexdigest()[:32]


def derive_rotating_machine_id(base_machine_id: str, generation: int) -> str:
    """机器指纹轮换代次派生（generation <= 0 时原样返回）。"""
    if generation <= 0:
        return base_machine_id
    return hashlib.sha256(f"{base_machine_id}#machine{int(generation)}".encode("utf-8")).hexdigest()[:32]


def machine_trace_id(machine_id: str, device_id: str) -> str:
    """``login_trace_id``：拼接串的尾部 16 字符（callback.go:55-63）。"""
    joined = machine_id + device_id
    return joined[-16:] if len(joined) >= 16 else joined.rjust(16, "0")


# ── 请求头（trae.ts 的 traeSOLOHeaders / traeOAuthHeaders） ───────────────

def _machine_id_generation() -> int:
    if not resolve_rotate_machine_id():
        return 0
    return _SEND_COUNT // 4


def trae_solo_headers(credential: dict, stream: bool, machine_id_generation: int = 0) -> dict[str, str]:
    """SOLO 对话 / 模型列表请求头。

    注意 ``Authorization`` / ``X-Cloudide-Token`` / ``X-Ide-Token`` 三处是**同一个**
    token —— 实测缺任一个都可能被上游拒绝。
    """
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream" if stream else "application/json",
        "User-Agent": USER_AGENT,
        "Authorization": f"Cloud-IDE-JWT {credential.get('access_token') or ''}",
        "X-Cloudide-Token": credential.get("access_token") or "",
        "X-Ide-Token": credential.get("access_token") or "",
        "X-Uid": credential.get("uid") or "",
        "X-App-Id": APP_ID,
        "X-App-Version": "default",
        "X-Ide-Version": IDE_VERSION,
        "X-Ide-Version-Code": IDE_VERSION_CODE,
        "X-App-Version-Code": IDE_VERSION_CODE,
        "X-Ide-Version-Type": "stable",
        "X-Device-Type": "macos",
        "X-OS-Version": OS_VERSION,
        "X-Device-Brand": DEVICE_BRAND,
        "Request-Traffic-Type": "prod",
    }
    machine_id = credential.get("machine_id") or ""
    if isinstance(machine_id, str) and machine_id != "":
        headers["X-Machine-Id"] = derive_rotating_machine_id(machine_id, machine_id_generation)
    device_id = credential.get("device_id") or ""
    if isinstance(device_id, str) and device_id != "":
        headers["X-Device-Id"] = device_id
    return headers


def trae_oauth_headers() -> dict[str, str]:
    """OAuth（ExchangeToken / GetUserInfo）请求头：无签名，仅 UA。"""
    return {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT}


def trae_ug_headers(credential: dict, checkin_device_generation: int = 0) -> dict[str, str]:
    """签到 / 积分请求头（``UgHeaders``）。"""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Authorization": f"Cloud-IDE-JWT {credential.get('access_token') or ''}",
        "X-User-Region": "CN",
    }
    device_id = credential.get("device_id") or ""
    if isinstance(device_id, str) and device_id != "":
        headers["X-Device-Id"] = derive_checkin_device_id(device_id, checkin_device_generation)
    return headers


# ── ExchangeToken / GetUserInfo 响应解析（trae.ts） ────────────────────────

def parse_trae_exchange_response(data: Any) -> dict | None:
    """``{Result:{Token,TokenExpireAt,TokenExpireDuration,RefreshToken,RefreshExpireAt}}``。"""
    if not isinstance(data, dict):
        return None
    result = data.get("Result") if data.get("Result") is not None else data.get("result")
    if not isinstance(result, dict):
        return None
    access_token = (read_string_field(result, "Token") or read_string_field(result, "token")
                    or read_string_field(result, "accessToken"))
    refresh_token = read_string_field(result, "RefreshToken") or read_string_field(result, "refreshToken")
    if access_token == "":
        return None
    token_expire_at = read_number_field(result, "TokenExpireAt")
    if token_expire_at is None:
        token_expire_at = read_number_field(result, "tokenExpireAt")
    token_expire_duration = read_number_field(result, "TokenExpireDuration")
    if token_expire_duration is None:
        token_expire_duration = read_number_field(result, "tokenExpireDuration")
    refresh_expire_at = read_number_field(result, "RefreshExpireAt")
    if refresh_expire_at is None:
        refresh_expire_at = read_number_field(result, "refreshExpireAt")
    return {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "tokenExpireAt": int(token_expire_at or 0),
        "tokenExpireDuration": int(token_expire_duration or 0),
        "refreshExpireAt": int(refresh_expire_at or 0),
    }


def parse_trae_user_info_response(data: Any) -> dict | None:
    """``{Result:{UserID,ScreenName,EnterpriseID,NonPlainTextMobile,NonPlainTextEmail}}``。"""
    if not isinstance(data, dict):
        return None
    result = data.get("Result") if data.get("Result") is not None else data.get("result")
    if not isinstance(result, dict):
        return None
    uid = (read_string_field(result, "UserID") or read_string_field(result, "userId")
           or read_string_field(result, "uid"))
    if uid == "":
        return None
    return {
        "uid": uid,
        "screenName": read_string_field(result, "ScreenName") or read_string_field(result, "screenName") or uid,
        "enterpriseId": read_string_field(result, "EnterpriseID") or read_string_field(result, "enterpriseId"),
        # ⚠️ 字段名是 **NonPlainTextMobile / NonPlainTextEmail**（脱敏形态）。
        "phone": read_string_field(result, "NonPlainTextMobile") or read_string_field(result, "nonPlainTextMobile"),
        "email": read_string_field(result, "NonPlainTextEmail") or read_string_field(result, "nonPlainTextEmail"),
    }


def _expires_at_from_exchange(exchange: dict, access_token: str, now_ms: int) -> str:
    """``expiresAt`` 归一化为**毫秒字符串**（毫秒值直接用 / 秒值 ×1000 / 相对秒数 / JWT exp）。"""
    token_expire_at = exchange.get("tokenExpireAt") or 0
    if isinstance(token_expire_at, (int, float)) and token_expire_at > 1e12:
        return str(int(token_expire_at))
    if isinstance(token_expire_at, (int, float)) and token_expire_at > 0:
        return str(int(token_expire_at * 1000))
    duration = exchange.get("tokenExpireDuration") or 0
    if isinstance(duration, (int, float)) and duration > 0:
        return str(int(now_ms + duration * 1000))
    exp = jwt_expires_at_ms(access_token)
    return "" if exp is None else str(exp)


def build_trae_credential(exchange: dict, user_info: dict, session: dict,
                          now_ms: int | None = None) -> dict:
    """由 ExchangeToken 结果 + 用户信息组装凭据。"""
    stamp = int(time.time() * 1000) if now_ms is None else now_ms
    credential = {
        "access_token": exchange.get("accessToken") or "",
        "refresh_token": exchange.get("refreshToken") or "",
        "expires_at": _expires_at_from_exchange(exchange, exchange.get("accessToken") or "", stamp),
        "uid": user_info.get("uid") or "",
        "nickname": user_info.get("screenName") or "",
        "machine_id": session.get("machineId") or "",
        "device_id": session.get("deviceId") or "",
        "enterprise_id": user_info.get("enterpriseId") or "",
    }
    phone = user_info.get("phone") or ""
    email = user_info.get("email") or ""
    if phone != "":
        credential["phone"] = phone
    if email != "":
        credential["email"] = email
    return credential


def apply_trae_refresh(previous: dict, exchange: dict, now_ms: int | None = None) -> dict:
    """用续期结果更新凭据（refresh_token 也会轮换，新值非空才覆盖）。"""
    stamp = int(time.time() * 1000) if now_ms is None else now_ms
    access_token = exchange.get("accessToken") or ""
    merged = dict(previous)
    merged["access_token"] = access_token
    fresh_refresh = exchange.get("refreshToken") or ""
    merged["refresh_token"] = fresh_refresh if fresh_refresh != "" else previous.get("refresh_token") or ""
    merged["expires_at"] = _expires_at_from_exchange(exchange, access_token, stamp)
    return merged


def trae_display_nickname(credential: dict, fallback_id: str) -> str:
    """展示名：脱敏手机号 → 脱敏邮箱 → ScreenName → uid（见 trae.ts 的报障说明）。"""
    for key in ("phone", "email", "nickname", "uid"):
        value = credential.get(key)
        if isinstance(value, str) and value.strip() != "":
            return value.strip()
    return fallback_id


# ── 错误分类（trae-errors.ts 的 classifyTraeError） ────────────────────────

SESSION_DEAD_MARKERS = ("login", "token 失效", "token invalid", "session", "unauthorized", "401")
PLAN_LIMIT_MARKERS = ('"code":1005', "1005")
QUOTA_EXCEEDED_MARKERS = ("4008", '"code":4008', "quota", "exceeded the quota")


def classify_trae_error(status: int, body: str) -> str:
    """判定顺序与 TS 完全一致（quota-exceeded **先于** 4011）。"""
    text = body or ""
    lower = text.lower()

    for marker in PLAN_LIMIT_MARKERS:
        if marker in text and "plan" in lower:
            return "hard-plan"

    for marker in QUOTA_EXCEEDED_MARKERS:
        if marker in text:
            return "quota-exceeded"

    if "4011" in text:
        return "soft-rate"

    if status == 401:
        for marker in SESSION_DEAD_MARKERS:
            if marker.lower() in lower:
                return "session-dead"
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


def error_code_for(kind: str, status: int | None = None) -> str:
    """TRAE 错误类别 → 项目内部失败码。"""
    if kind in ("hard-plan", "soft-rate", "quota-exceeded"):
        return CODE["quota"]
    if kind == "session-dead":
        return CODE["credential"]
    if kind == "server":
        return CODE["server"]
    if kind in ("client", "not-found"):
        return CODE["client"]
    if status == 429:
        return CODE["quota"]
    if status in (401, 403):
        return CODE["credential"]
    if status is not None and status >= 500:
        return CODE["server"]
    return CODE["server"]


def error_detail(body: str) -> str:
    """从错误体提取可读 detail（``code=… message msg``）。"""
    try:
        data = json.loads(body)
    except ValueError:
        return body
    if not isinstance(data, dict):
        return body
    parts: list[str] = []
    code = data.get("code")
    if isinstance(code, (int, str)) and not isinstance(code, bool):
        parts.append(f"code={code}")
    for key in ("message", "msg"):
        value = data.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts) if parts else body


def trae_stream_error_message(code: int, message: str, model: str) -> str:
    """组合 SOLO 流内 ``event:error`` 的文案（4001 追加真实成因提示）。"""
    base = f"trae: {message} (code={code})"
    if code != 4001:
        return base
    return (f"{base} —— 模型「{model}」不被上游接受：它通常是「仅可见但不可调用」的"
            "自定义模型（需先在 TRAE IDE 内自行配置供应商），请改用模型列表中的其它模型")


# ── 模型目录解析（trae.ts 的 parseTraeConfigEntry / batch 合并规则） ───────

def _read_context_window_field(entry: dict) -> int | None:
    """``context_window_tokens.dev``（缺失回退 ``max``）。"""
    raw = entry.get("context_window_tokens") if entry.get("context_window_tokens") is not None \
        else entry.get("ContextWindowTokens")
    if not isinstance(raw, dict):
        return None
    value = read_number_field(raw, "dev")
    if value is None:
        value = read_number_field(raw, "Dev")
    if value is None:
        value = read_number_field(raw, "max")
    if value is None:
        value = read_number_field(raw, "Max")
    return int(value) if value is not None and value > 0 else None


def _read_max_context_window_field(entry: dict) -> int | None:
    """``context_window_tokens.max``（Max 模式专用，不可与 ``dev`` 混用）。"""
    raw = entry.get("context_window_tokens") if entry.get("context_window_tokens") is not None \
        else entry.get("ContextWindowTokens")
    if not isinstance(raw, dict):
        return None
    value = read_number_field(raw, "max")
    if value is None:
        value = read_number_field(raw, "Max")
    return int(value) if value is not None and value > 0 else None


def _read_detail_max_tokens(entry: dict, preferred_suffix: str = "__dev") -> int | None:
    """``model_detail_list[].max_tokens``：优先取 ``model_name`` 以 suffix 结尾的那条。"""
    raw = entry.get("model_detail_list") if entry.get("model_detail_list") is not None \
        else entry.get("ModelDetailList")
    if not isinstance(raw, list) or not raw:
        return None
    details = [item for item in raw if isinstance(item, dict)]
    chosen = next((item for item in details if read_string_field(item, "model_name").endswith(preferred_suffix)), None)
    if chosen is None:
        chosen = details[0] if details else None
    if chosen is None:
        return None
    value = read_number_field(chosen, "max_tokens")
    if value is None:
        value = read_number_field(chosen, "MaxTokens")
    return int(value) if value is not None and value > 0 else None


def _read_reasoning_effort_config(entry: dict) -> dict | None:
    """``reasoning_effort_config``：``{default_level, options[], support_thinking}``。"""
    raw = entry.get("reasoning_effort_config") if entry.get("reasoning_effort_config") is not None \
        else entry.get("ReasoningEffortConfig")
    if not isinstance(raw, dict):
        return None
    options: list[str] = []
    raw_options = raw.get("options") if raw.get("options") is not None else raw.get("Options")
    if isinstance(raw_options, list):
        for item in raw_options:
            if isinstance(item, str) and item.strip() != "":
                options.append(item.strip())
            elif isinstance(item, dict):
                wire = (read_string_field(item, "openclawLevel") or read_string_field(item, "level")
                        or read_string_field(item, "Level"))
                if wire.strip() != "":
                    options.append(wire.strip())
    default_level = read_string_field(raw, "default_level") or read_string_field(raw, "DefaultLevel")
    support_thinking = read_boolean_field(raw, "support_thinking")
    if support_thinking is None:
        support_thinking = read_boolean_field(raw, "SupportThinking")
    if not options and default_level == "" and support_thinking is None:
        return None
    return {"options": options, "defaultLevel": default_level, "supportThinking": support_thinking}


def _strongest_effort(options: list[str]) -> str:
    """挑最强档：显式 ``max`` → 强度序最高 → 数组末项。"""
    if not options:
        return ""
    if "max" in options:
        return "max"
    best = ""
    best_rank = -1
    for option in options:
        if option in REASONING_LADDER:
            rank = REASONING_LADDER.index(option)
            if rank > best_rank:
                best, best_rank = option, rank
    return best or options[-1]


def _default_effort(config: dict) -> str:
    """默认档：**上游 ``default_level`` 优先**，且必须真的落在 ``options`` 内。"""
    declared = config.get("defaultLevel") or ""
    if declared != "" and declared in (config.get("options") or []):
        return declared
    return _strongest_effort(config.get("options") or [])


def read_consumption_rate(entry: dict) -> float | None:
    """``display_contact_config``（**JSON 字符串**）里的消耗倍率；``rate=0`` 合法（免费）。"""
    raw = entry.get("display_contact_config") if entry.get("display_contact_config") is not None \
        else entry.get("DisplayContactConfig")
    config = _json_object(raw)
    if config is None:
        return None
    rate = config.get("consumption_rate") if config.get("consumption_rate") is not None \
        else config.get("ConsumptionRate")
    if not isinstance(rate, dict):
        return None
    if read_boolean_field(rate, "enable") is False:
        return None
    data = rate.get("data") if rate.get("data") is not None else rate.get("Data")
    if not isinstance(data, dict):
        return None
    value = read_number_field(data, "rate")
    return value if value is not None and value >= 0 else None


def trae_display_name(model: dict) -> str:
    """模型选择器展示名：``模型名 · x倍率``（``rate=0`` 显示「免费」，无倍率只显示名字）。"""
    name = model.get("name") or model.get("id") or ""
    rate = model.get("creditsRate")
    if rate is None:
        return name
    current = "免费" if rate == 0 else f"x{rate}"
    return f"{name} · {current}"


def parse_trae_config_entry(entry: Any, channel: str | None) -> dict | None:
    """解析单条 ``config_info_list`` 条目（两个端点形状一致）。"""
    if not isinstance(entry, dict):
        return None
    model_id = read_string_field(entry, "config_name") or read_string_field(entry, "ConfigName")
    if model_id == "":
        return None
    display = entry.get("display_config") if entry.get("display_config") is not None \
        else entry.get("DisplayConfig")
    display_record = display if isinstance(display, dict) else None
    name = read_string_field(display_record, "display_name") or model_id if display_record is not None else model_id
    is_custom = None
    if display_record is not None:
        is_custom = read_boolean_field(display_record, "is_custom_model")
        if is_custom is None:
            is_custom = read_boolean_field(display_record, "IsCustomModel")
    is_hidden = read_boolean_field(entry, "is_invisible_to_user")
    if is_hidden is None:
        is_hidden = read_boolean_field(entry, "IsInvisibleToUser")
    is_enabled = read_boolean_field(entry, "config_switch")
    if is_enabled is None:
        is_enabled = read_boolean_field(entry, "ConfigSwitch")
    usage = read_string_field(entry, "usage") or read_string_field(entry, "Usage")
    multimodal = None
    if display_record is not None:
        multimodal = read_boolean_field(display_record, "multimodal")
        if multimodal is None:
            multimodal = read_boolean_field(display_record, "Multimodal")
    max_mode = None
    if display_record is not None:
        max_mode = read_boolean_field(display_record, "max_mode")
        if max_mode is None:
            max_mode = read_boolean_field(display_record, "MaxMode")
    reasoning = _read_reasoning_effort_config(entry)
    model = {
        "id": model_id,
        "name": name,
        "isCustomModel": is_custom,
        "isHidden": is_hidden,
        "isEnabled": is_enabled,
        "usage": usage,
        "contextWindow": _read_context_window_field(entry),
        "maxOutputTokens": _read_detail_max_tokens(entry),
        "maxContextWindow": _read_max_context_window_field(entry),
        "maxModeOutputTokens": _read_detail_max_tokens(entry, "__max"),
        "maxMode": max_mode,
        "multimodal": multimodal,
        "reasoningConfig": reasoning,
        "creditsRate": read_consumption_rate(entry),
    }
    if channel is not None:
        model["function"] = channel
    return model


def parse_trae_batch_model_list(body: Any, channel_priority: list[str] | None = None) -> list[dict]:
    """解析 ``batch_get_detail_param``：白名单准入 + 硬性过滤 + 择优合并。

    - ``function`` 不在白名单（或未声明）→ 整组丢弃（发出去必然被上游拒）；
    - ``usage`` 非 ``chat_completion`` / ``config_switch === false`` /
      ``is_invisible_to_user === true`` → 剔除；
    - 同一 ``config_name`` 多条时：**空档位不得覆盖有档位**，两侧都有档位按通道
      优先级取更靠前者，其余沿用「后覆盖前」。
    """
    if not isinstance(body, dict):
        return []
    priority = list(channel_priority if channel_priority is not None else DEFAULT_CHANNELS)
    groups = body.get("function_configs") if body.get("function_configs") is not None \
        else body.get("FunctionConfigs")
    if not isinstance(groups, list):
        return []

    def rank_of(channel: str) -> int:
        return priority.index(channel) if channel in priority else -1

    def declares_effort(model: dict) -> bool:
        config = model.get("reasoningConfig")
        if config is None:
            return False
        if config.get("supportThinking") is False:
            return False
        return len(config.get("options") or []) > 0

    by_id: dict[str, dict] = {}
    chosen_rank: dict[str, int] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        channel = read_string_field(group, "function") or read_string_field(group, "Function")
        if channel == "" or rank_of(channel) < 0:
            continue
        items = group.get("config_info_list") if group.get("config_info_list") is not None \
            else group.get("ConfigInfoList")
        if not isinstance(items, list):
            continue
        for item in items:
            model = parse_trae_config_entry(item, channel)
            if model is None:
                continue
            usage = model.get("usage")
            if usage not in (None, "", "chat_completion"):
                continue
            if model.get("isEnabled") is False:
                continue
            if model.get("isHidden") is True:
                continue
            incumbent = by_id.get(model["id"])
            if incumbent is None:
                by_id[model["id"]] = model
                chosen_rank[model["id"]] = rank_of(channel)
                continue
            incumbent_effort = declares_effort(incumbent)
            candidate_effort = declares_effort(model)
            if incumbent_effort and not candidate_effort:
                continue
            if incumbent_effort and candidate_effort and rank_of(channel) >= chosen_rank.get(model["id"], 0):
                continue
            by_id[model["id"]] = model
            chosen_rank[model["id"]] = rank_of(channel)
    return list(by_id.values())


def is_callable(model: dict) -> bool:
    """可调用：``is_custom_model !== true``（必然 4001）且未被上游停用。"""
    return model.get("isCustomModel") is not True and model.get("isEnabled") is not False


def _catalog_row(model: dict) -> dict:
    """把解析出的远端条目投影成渠道目录行（含 stream 需要的通道 / Max 模式元数据）。"""
    reasoning_config = model.get("reasoningConfig") or {}
    options = list(reasoning_config.get("options") or [])
    reasoning = bool(options) and reasoning_config.get("supportThinking") is not False
    row = {
        "id": model["id"],
        "name": trae_display_name(model),
        "channel": model.get("function") or FUNCTION,
        "contextWindow": model.get("contextWindow"),
        "maxOutput": model.get("maxOutputTokens") or FALLBACK_MAX_OUTPUT_TOKENS,
        "vision": model.get("multimodal") is True,
        "reasoning": reasoning,
        "efforts": options or None,
        "defaultEffort": _default_effort(reasoning_config) if reasoning else None,
        "maxMode": model.get("maxMode") is True,
        "maxContextWindow": model.get("maxContextWindow"),
        "maxModeOutputTokens": model.get("maxModeOutputTokens"),
        "isHidden": model.get("isHidden") is True,
    }
    return row


def fallback_catalog() -> list[dict]:
    """静态兜底目录（过滤 ``isHidden``；``maxOutput`` 用产品级兜底值）。"""
    rows = []
    for model in FALLBACK_MODELS:
        if model.get("isHidden") is True:
            continue
        rows.append({
            "id": model["id"],
            "name": model["name"],
            "channel": FUNCTION,
            "contextWindow": model["contextWindow"],
            "maxOutput": FALLBACK_MAX_OUTPUT_TOKENS,
            "vision": False,
            "reasoning": False,
            "efforts": None,
            "defaultEffort": None,
            "maxMode": False,
            "maxContextWindow": None,
            "maxModeOutputTokens": None,
            "isHidden": False,
        })
    return rows


# ── HTTP 辅助 ──────────────────────────────────────────────────────────────

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


async def _post_json(url: str, headers: dict[str, str], payload: dict,
                     timeout_s: float = TRAE_REQUEST_TIMEOUT_S) -> tuple[int, str, Any]:
    """POST 一次并返回 ``(status, text, parsed_or_None)``；网络失败抛 TRANSPORT。"""
    client = await get_client()
    try:
        response = await client.post(url, headers=headers, content=json.dumps(payload, ensure_ascii=False),
                                     timeout=timeout_s)
    except httpx.HTTPError as error:
        raise UpstreamError(f"trae: transport error: {error}", CODE["transport"])
    text = response.text
    try:
        parsed: Any = json.loads(text)
    except ValueError:
        parsed = None
    return response.status_code, text, parsed


# ── ExchangeToken / GetUserInfo（trae-oauth.ts 的 exchangeTraeCallback） ──

async def exchange_token(refresh_token: str, *, host: str = TRAE_OAUTH_HOST) -> dict:
    """``ClientID`` + ``RefreshToken`` + ``ClientSecret: '-'`` → access/refresh 轮换。"""
    payload = {"ClientID": CLIENT_ID, "RefreshToken": refresh_token, "ClientSecret": "-", "UserID": ""}
    status, text, parsed = await _post_json(f"{host}{TRAE_EXCHANGE_PATH}", trae_oauth_headers(), payload)
    if status >= 400:
        kind = classify_trae_error(status, text)
        raise UpstreamError(f"trae: ExchangeToken HTTP {status}（{error_detail(text)[:200]}）",
                            error_code_for(kind, status), status=status, kind=kind)
    exchange = parse_trae_exchange_response(parsed)
    if exchange is None:
        raise UpstreamError("trae: ExchangeToken 响应缺少 Token", CODE["server"], status=status)
    return exchange


async def fetch_user_info(access_token: str, *, host: str = TRAE_OAUTH_HOST) -> dict | None:
    """``GetUserInfo``：补 uid / ScreenName / EnterpriseID / 脱敏手机号邮箱。失败返回 None。"""
    headers = trae_oauth_headers()
    headers["X-Cloudide-Token"] = access_token
    try:
        status, _text, parsed = await _post_json(
            f"{host}{TRAE_USER_INFO_PATH}", headers, {"ReqSource": "IDE", "IDEVersion": IDE_VERSION})
    except UpstreamError:
        return None
    if status >= 400:
        return None
    return parse_trae_user_info_response(parsed)


def fix_nickname_mojibake(raw: str, uid: str) -> str:
    """修复回调 ``userInfo.ScreenName`` 的双重编码乱码；无 CJK 时回退「用户+uid末4位」。"""
    if raw == "":
        return raw
    try:
        fixed = raw.encode("latin-1", "strict").decode("utf-8", "strict")
        if fixed != "" and "\ufffd" not in fixed and all(ord(ch) >= 32 for ch in fixed):
            return fixed
    except Exception:  # noqa: BLE001
        pass
    if not _CJK.search(raw):
        return f"用户{uid[-4:]}"
    return raw


def parse_json_param(raw: str | None) -> dict | None:
    """解析回调里 URL 编码的 JSON 参数（``userInfo`` / ``userJwt``），容忍双重编码。"""
    if raw is None or raw == "":
        return None
    from urllib.parse import unquote

    candidates = [raw]
    try:
        unescaped = unquote(raw)
        if unescaped != raw:
            candidates.append(unescaped)
    except Exception:  # noqa: BLE001
        pass
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def parse_trae_callback(raw_url: str) -> dict:
    """解析 TRAE 登录回调，返回 ``{"ok":bool, "info":{...}, "reason":str, "authCodeFlow":bool}``。

    ⚠️ 回调**直接回传 token**（``refreshToken`` / ``userInfo`` / ``userJwt``），不是
    OAuth 的 ``?code=``；但**带 code 的回调不是无效回调**（PKCE 新流程），此处如实
    解出 ``authCode`` 并由调用方明确报「暂不支持」。
    """
    from urllib.parse import parse_qs, urlsplit

    url = raw_url if raw_url.startswith("http") else f"http://127.0.0.1{raw_url}"
    try:
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    except Exception:  # noqa: BLE001
        return {"ok": False, "info": None, "reason": "回调 URL 无法解析", "authCodeFlow": False}

    def one(key: str) -> str:
        values = query.get(key)
        return values[0] if values else ""

    user_info = parse_json_param(one("userInfo"))
    user_jwt = parse_json_param(one("userJwt"))
    auth_code_info = parse_json_param(one("authCodeInfo"))

    refresh_token = one("refreshToken")
    uid = read_string_field(user_info, "UserID")
    nickname_raw = read_string_field(user_info, "ScreenName")
    # ⚠️ 回调字段名是 **TenantID**（不是 EnterpriseID）。
    enterprise_id = read_string_field(user_info, "TenantID")
    jwt_token = read_string_field(user_jwt, "Token")
    jwt_refresh = read_string_field(user_jwt, "RefreshToken")
    if refresh_token == "":
        refresh_token = jwt_refresh

    auth_code_candidates = [
        one("code"), one("authCode"),
        read_string_field(auth_code_info, "code"), read_string_field(auth_code_info, "authCode"),
        one("authCodeInfo"),
    ]
    auth_code = next((c.strip() for c in auth_code_candidates if c.strip() != ""), "")

    info = {
        "refreshToken": refresh_token,
        "accessToken": jwt_token if refresh_token == "" else "",
        "uid": uid,
        "nickname": fix_nickname_mojibake(nickname_raw, uid),
        "enterpriseId": enterprise_id,
    }
    if auth_code != "":
        info["authCode"] = auth_code

    if info["refreshToken"] == "" and info["accessToken"] == "":
        if auth_code != "":
            return {"ok": False, "info": None, "authCodeFlow": True,
                    "reason": "上游返回了 PKCE 授权码（code/authCodeInfo），本实现暂不支持该流程；"
                              "请确认 TRAE 授权页是否已切换到新流程"}
        return {"ok": False, "info": None, "authCodeFlow": False,
                "reason": "回调未携带 refreshToken / userJwt.Token / code"}
    return {"ok": True, "info": info, "reason": "", "authCodeFlow": False}


async def exchange_trae_callback(callback: dict, session: dict, *, host: str = TRAE_OAUTH_HOST,
                                 now_ms: int | None = None) -> dict:
    """回调凭证 → 最终凭据：有 refreshToken 走 ExchangeToken，否则直接用 userJwt.Token。"""
    if callback.get("refreshToken"):
        exchange = await exchange_token(callback["refreshToken"], host=host)
    else:
        exchange = {"accessToken": callback.get("accessToken") or "", "refreshToken": "",
                    "tokenExpireAt": 0, "tokenExpireDuration": 0, "refreshExpireAt": 0}

    user_info = {
        "uid": callback.get("uid") or "",
        "screenName": callback.get("nickname") or "",
        "enterpriseId": callback.get("enterpriseId") or "",
        # ⚠️ 回调的 userInfo **不含**脱敏手机号 / 邮箱，只在 GetUserInfo 里。
        "phone": "",
        "email": "",
    }
    fetched = await fetch_user_info(exchange.get("accessToken") or "", host=host)
    if fetched is not None:
        user_info = {
            "uid": fetched["uid"],
            "screenName": fetched["screenName"] or user_info["screenName"],
            "enterpriseId": fetched["enterpriseId"] or user_info["enterpriseId"],
            "phone": fetched["phone"],
            "email": fetched["email"],
        }
    if user_info["uid"] == "":
        raise UpstreamError("trae: 未能确定 uid（回调 userInfo 与 GetUserInfo 均为空）", CODE["server"])
    if (exchange.get("accessToken") or "") == "":
        raise UpstreamError("trae: 换 token 后没有 accessToken", CODE["server"])
    return build_trae_credential(exchange, user_info, session, now_ms)


# ── 登录（trae-oauth.ts 的 runTraeLoginFlow / startCallbackServer） ───────

def build_trae_login_url(machine_id: str, device_id: str, callback_url: str) -> str:
    """完整 17 参数登录 URL（``auth_callback_url`` 名字不能错，否则页面永久「认证中」）。"""
    from urllib.parse import urlencode

    params = {
        "login_version": "1",
        "auth_from": "solo",
        "login_channel": "native_ide",
        "plugin_version": PLUGIN_VERSION,
        "auth_type": "local",
        "client_id": CLIENT_ID,
        "redirect": "0",
        "login_trace_id": machine_trace_id(machine_id, device_id),
        "auth_callback_url": callback_url,
        "machine_id": machine_id,
        "device_id": device_id,
        "x_device_id": device_id,
        "x_machine_id": machine_id,
        "x_device_brand": "PC",
        "x_device_type": "PC",
        "x_os_version": "1.0",
        "x_app_version": IDE_VERSION,
        "x_app_type": "stable",
    }
    return f"{TRAE_CONSOLE_HOST}/authorization?{urlencode(params)}"


def _http_response(status: int, reason: str, body: str) -> bytes:
    payload = body.encode("utf-8")
    return (f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n").encode("latin-1") + payload


async def run_login(*, open_browser: bool = True, timeout_s: float = TRAE_LOGIN_TIMEOUT_S,
                    callback_port: int = TRAE_CALLBACK_PORT) -> dict:
    """完整登录：起本地回调服务器 → 打开授权页 → 等回调 → ExchangeToken + GetUserInfo。

    首选端口被占用时自动回退到系统分配的随机端口（``auth_callback_url`` 必须与实际
    监听端口一致，否则回调打到没人监听的地址上）。
    """
    machine_id = generate_machine_id()
    device_id = generate_device_id()
    session = {"machineId": machine_id, "deviceId": device_id}
    state: dict[str, Any] = {}
    done = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            target = (request_line.split(" ") + ["", ""])[1]
            if not target.startswith(TRAE_CALLBACK_PATH):
                writer.write(_http_response(404, "Not Found", "not found"))
                await writer.drain()
                return
            parsed = parse_trae_callback(target)
            if not parsed["ok"]:
                writer.write(_http_response(400, "Bad Request", f"TRAE 登录回调无效：{parsed['reason']}"))
                await writer.drain()
                state["error"] = f"TRAE 登录回调无效：{parsed['reason']}"
            else:
                writer.write(_http_response(200, "OK", "已收到 TRAE 授权，正在换取凭据…可以关闭此页面。"))
                await writer.drain()
                state["callback"] = parsed["info"]
            done.set()
        except Exception as error:  # noqa: BLE001
            state["error"] = f"TRAE 登录回调处理失败：{error}"
            done.set()
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    server = None
    port = callback_port
    for candidate in (callback_port, 0):
        try:
            server = await asyncio.start_server(handle, "127.0.0.1", candidate)
            port = server.sockets[0].getsockname()[1]
            break
        except OSError:
            server = None
    if server is None:
        raise UpstreamError(f"trae: TRAE 回调端口 {callback_port} 无法监听；端口可能已被其它程序占用",
                            CODE["server"])

    callback_url = f"http://127.0.0.1:{port}{TRAE_CALLBACK_PATH}"
    login_url = build_trae_login_url(machine_id, device_id, callback_url)
    if open_browser:
        _open_external(login_url)
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        raise UpstreamError("trae: TRAE 登录超时（等待浏览器回调）", CODE["timeout"])
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    if state.get("error"):
        raise UpstreamError(str(state["error"]), CODE["credential"])
    callback = state.get("callback")
    if not isinstance(callback, dict):
        raise UpstreamError("trae: 登录回调缺失", CODE["credential"])

    credential = await exchange_trae_callback(callback, session)
    credential["login_url"] = login_url
    return credential


# ── 续期（trae-auth.ts 的 refreshCredential / applyTraeRefresh） ──────────

async def refresh_credential(credential: dict) -> dict:
    """``ExchangeToken`` 静默续期；access_token 与 refresh_token 都会被轮换。"""
    if not is_refreshable(credential):
        raise UpstreamError("trae: 无 refresh_token，请重新登录", CODE["credential"])
    host = credential.get("api_host") or TRAE_OAUTH_HOST
    payload = {
        "ClientID": CLIENT_ID,
        "RefreshToken": credential.get("refresh_token") or "",
        "ClientSecret": "-",
        "UserID": "",
    }
    try:
        status, text, parsed = await _post_json(f"{host}{TRAE_EXCHANGE_PATH}", trae_oauth_headers(), payload)
    except UpstreamError as error:
        # 传输层失败：不能判为终态 —— 网络抖动不该让用户重新登录。
        raise UpstreamError(f"trae: 续期网络失败：{error.message}", CODE["transport"])

    exchange = parse_trae_exchange_response(parsed) if parsed is not None else None
    if exchange is None or (exchange.get("accessToken") or "") == "":
        kind = classify_trae_error(status, text)
        # 终态三条独立依据：401/403、分类 session-dead、2xx + JSON 却无 token。
        no_token_in_success = 200 <= status < 300 and parsed is not None
        if status in (401, 403) or kind == "session-dead" or no_token_in_success:
            raise UpstreamError("trae: refresh_token 已失效，请重新登录", CODE["credential"], status=status)
        raise UpstreamError(f"trae: 续期失败（HTTP {status}）：{text[:200]}",
                            error_code_for(kind, status), status=status)
    return apply_trae_refresh(credential, exchange)


# ── 模型目录（trae-auth.ts 的 fetchModelsUncached + parseTraeBatchModelList） ──

async def fetch_models(credential: dict) -> dict:
    """``batch_get_detail_param`` 拉取目录；任何失败都回退兜底表（**不抛错**）。"""
    access_token = credential.get("access_token") or ""
    if access_token == "":
        return {"models": fallback_catalog(), "source": "fallback", "reason": "no access_token"}
    payload = {
        "functions": list(BATCH_FUNCTIONS),
        "agent_type": "",
        "current_config_info": {"config_name": "", "is_custom_model": False},
        "mode_type": 0,
        "access_type": 0,
        "ab_force_vids": "",
        "ab_autotest_advanced_mode": 0,
        "show_custom_model": True,
    }
    try:
        status, text, parsed = await _post_json(f"{TRAE_AGENT_HOST}{TRAE_BATCH_MODELS_PATH}",
                                                trae_solo_headers(credential, False), payload)
        if status >= 400:
            return {"models": fallback_catalog(), "source": "fallback", "reason": f"HTTP {status}"}
        models = parse_trae_batch_model_list(parsed, resolve_channel_list())
        rows = [_catalog_row(model) for model in models if is_callable(model) and model.get("isHidden") is not True]
        if not rows:
            return {"models": fallback_catalog(), "source": "fallback", "reason": "empty catalog"}
        return {"models": rows, "source": "remote"}
    except Exception as error:  # noqa: BLE001
        return {"models": fallback_catalog(), "source": "fallback", "reason": str(error)}


# ── OpenAI → SOLO 载荷转换（trae.ts 的 transformToSOLOBody） ──────────────

def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text")))
    return "".join(parts)


def _transform_solo_message(msg: Any) -> dict:
    """单条消息转换：assistant ``tool_calls.function`` → ``function_call``；content 字符串数组化。"""
    result = dict(msg) if isinstance(msg, dict) else {}
    if result.get("role") == "assistant":
        tool_calls = result.get("tool_calls")
        if isinstance(tool_calls, list):
            kept = []
            for call in tool_calls:
                if not isinstance(call, dict):
                    continue
                item = dict(call)
                if isinstance(item.get("function"), dict):
                    item["function_call"] = item.pop("function")
                function_call = item.get("function_call")
                # 无 function_call.name 的 tool_call 剔除（空名字块会被上游拒绝）。
                if not isinstance(function_call, dict) or not isinstance(function_call.get("name"), str) \
                        or function_call["name"].strip() == "":
                    continue
                kept.append(item)
            if kept:
                result["tool_calls"] = kept
            else:
                result.pop("tool_calls", None)
    content = result.get("content")
    if isinstance(content, str):
        result["content"] = [{"type": "text", "text": content}]
    # 已是数组 → 透传（多模态 / 图片 parts 上游直接接受）
    return result


def _normalize_tool_choice(body: dict) -> None:
    """``tool_choice`` 归一化：none → 删 tools；auto/required 保留；function → 名字字符串。"""
    choice = body.get("tool_choice")
    if choice is None:
        return

    def suppress() -> None:
        body.pop("tools", None)
        body.pop("functions", None)

    if isinstance(choice, str):
        if choice.strip().lower() == "none":
            body.pop("tool_choice", None)
            suppress()
        return
    if isinstance(choice, dict):
        typ = choice.get("type") if isinstance(choice.get("type"), str) else ""
        typ = typ.strip().lower()
        if typ == "none":
            body.pop("tool_choice", None)
            suppress()
        elif typ in ("auto", "required"):
            body["tool_choice"] = typ
        elif typ == "function":
            fn = choice.get("function") if isinstance(choice.get("function"), dict) else {}
            name = fn.get("name") if isinstance(fn.get("name"), str) else ""
            if name == "" and isinstance(choice.get("name"), str):
                name = choice["name"]
            body["tool_choice"] = name.strip() if name.strip() != "" else "auto"
        else:
            body.pop("tool_choice", None)
        return
    body.pop("tool_choice", None)


def _normalize_tools(body: dict) -> None:
    """SOLO 要求 ``tools[].function.parameters`` 是 **JSON 字符串**（OpenAI 是对象）。"""
    raw = body.get("tools")
    if not isinstance(raw, list) or not raw:
        return
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entry = dict(item)
        fn = entry.get("function")
        if not isinstance(fn, dict):
            continue
        fn = dict(fn)
        params = fn.get("parameters")
        if isinstance(params, dict):
            fn["parameters"] = json.dumps(params, ensure_ascii=False)
        entry["function"] = fn
        out.append(entry)
    if out:
        body["tools"] = out
    else:
        body.pop("tools", None)


def trae_max_mode_fields(max_context: Any, output_max: Any = None) -> dict:
    """把会话钉到 Max 模式（1M）：三件套 + ``strategy=max``，缺一不可。"""
    context = int(max_context) if isinstance(max_context, (int, float)) and max_context > 0 else TRAE_MAX_CONTEXT_TOKENS
    output = int(output_max) if isinstance(output_max, (int, float)) and output_max > 0 else TRAE_MAX_OUTPUT_TOKENS
    return {
        "model_auto_selection": {"strategy": "max", "fallback_to_advance_model": None, "entitlement_id": None},
        "model_selection_strategy": "max",
        "mode_type": TRAE_MAX_MODE_TYPE,
        "context_window_size": context,
        "prompt_max_tokens": TRAE_MAX_PROMPT_TOKENS,
        "max_tokens": output,
    }


def transform_to_solo_body(openai_body: dict, model_mapping: str | None = None,
                           channel: str | None = None) -> dict:
    """OpenAI 请求体 → SOLO 请求体（逐条对齐 Go 端 ``payload.go:PrepareBody``）。"""
    body = dict(openai_body)
    body["stream"] = True
    body["function"] = channel if isinstance(channel, str) and channel != "" else FUNCTION

    messages = body.get("messages")
    if isinstance(messages, list):
        body["messages"] = [_transform_solo_message(msg) for msg in messages]

    model = body.get("model") if isinstance(body.get("model"), str) else ""
    base_model = model.split("__")[0] if "__" in model else model
    config_name = model_mapping if isinstance(model_mapping, str) and model_mapping != "" else (base_model or DEFAULT_MODEL)
    body["config_name"] = config_name
    body["model"] = config_name

    _normalize_tool_choice(body)
    _normalize_tools(body)
    return body


# ── SOLO → 内部 chunk（trae.ts 的 parseTraeSSELine + trae-adapter.ts 的 consumeSse） ──

def normalize_trae_tool_calls(calls: Any) -> list:
    """``function_call`` → ``function``，并清掉 SOLO 专属字段（namespace / partial_arguments）。"""
    if not isinstance(calls, list):
        return []
    out = []
    for call in calls:
        if not isinstance(call, dict):
            continue
        item = dict(call)
        if isinstance(item.get("function_call"), dict):
            item["function"] = dict(item["function_call"])
            item.pop("function_call", None)
        fn = item.get("function")
        if isinstance(fn, dict):
            fn = dict(fn)
            fn.pop("namespace", None)
            fn.pop("partial_arguments", None)
            item["function"] = fn
        out.append(item)
    return out


def parse_trae_sse_line(event_name: str, data_line: str) -> dict:
    """解析一条 SOLO 事件（``event:`` 行 + ``data:`` 行的 JSON）。"""
    event = (event_name or "").strip()
    parsed: dict = {"event": event}
    if data_line == "":
        return parsed
    try:
        raw = json.loads(data_line)
    except ValueError:
        return parsed
    if not isinstance(raw, dict):
        return parsed
    if event == "output":
        if isinstance(raw.get("response"), str):
            parsed["response"] = raw["response"]
        if isinstance(raw.get("reasoning_content"), str):
            parsed["reasoningContent"] = raw["reasoning_content"]
        if raw.get("tool_calls") is not None and isinstance(raw.get("tool_calls"), list):
            parsed["toolCalls"] = normalize_trae_tool_calls(raw["tool_calls"])
    elif event == "token_usage":
        parsed["usage"] = raw
    elif event == "done":
        if isinstance(raw.get("finish_reason"), str):
            parsed["finishReason"] = raw["finish_reason"]
    elif event == "error":
        if isinstance(raw.get("code"), (int, float)) and not isinstance(raw.get("code"), bool):
            parsed["errorCode"] = int(raw["code"])
        if isinstance(raw.get("message"), str):
            parsed["errorMessage"] = raw["message"]
    return parsed


def has_usable_tool_name(name: Any) -> bool:
    """判据必须落在原始值上（``None`` 经 str() 会变成非空的 ``"None"``）。"""
    return isinstance(name, str) and name.strip() != ""


def normalize_tool_arguments(raw: str) -> str:
    """空串 / 非法 JSON / 非对象 → ``{}``。"""
    trimmed = (raw or "").strip()
    if trimmed == "":
        return "{}"
    try:
        parsed = json.loads(trimmed)
    except ValueError:
        return "{}"
    if parsed is None or not isinstance(parsed, dict):
        return "{}"
    return trimmed


def is_truncated_arguments(raw: str) -> bool:
    """非空但无法解析 = 参数分片在流中丢了（不能补 ``{}`` 了事）。"""
    trimmed = (raw or "").strip()
    if trimmed == "":
        return False
    try:
        json.loads(trimmed)
    except ValueError:
        return True
    return False


def is_prose_truncated_by_stop_string(text: str) -> bool:
    """正文疑似被上游停止串（``</think>`` 之类）掐断：奇数反引号 + 以未闭合引号收尾。"""
    if not text:
        return False
    tail = text.rstrip()
    if tail == "":
        return False
    if tail.count("`") % 2 == 0:
        return False
    return tail.endswith("`") or tail.endswith("<") or tail.endswith("</think")


def _map_usage(usage: dict) -> dict:
    """``token_usage`` → 内部 usage（字段名照抄本项目约定）。"""
    def number(key: str) -> int:
        value = usage.get(key)
        return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

    prompt = number("prompt_tokens")
    completion = number("completion_tokens")
    reasoning = number("reasoning_tokens")
    out = {
        "inputTokens": prompt,
        "outputTokens": completion,
        "totalTokens": prompt + completion,
        "reasoningTokens": reasoning,
    }
    cached = number("cached_tokens")
    if cached > 0:
        out["cacheReadTokens"] = cached
    return out


async def _iter_lines(source: AsyncIterator[bytes]) -> AsyncIterator[str]:
    """按 ``\\n`` 切行（保持与 TS 的 ``buffer.indexOf('\\n')`` 同语义）。"""
    buffer = ""
    async for chunk in source:
        buffer += chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            yield line
    if buffer != "":
        yield buffer


async def _consume_solo(lines: AsyncIterator[str], model: str) -> AsyncIterator[dict]:
    """SOLO 自定义 SSE → 内部 chunk。

    事件格式（solosse.go）：

    ``event:output`` / ``data:{"response":"<增量>","reasoning_content":"<思考增量>","tool_calls":null|[…]``
    ``event:token_usage`` / ``data:{"prompt_tokens":21,"completion_tokens":142,…}``
    ``event:done`` / ``data:{"finish_reason":"stop"}``
    ``event:error`` / ``data:{"code":4008,"message":"quota exceeded"}``
    """
    blocks: list[dict] = []
    next_index = 0
    tool_calls: dict[int, dict] = {}
    tool_ids: dict[int, str] = {}
    tool_order: list[int] = []
    current_event = ""
    current_data = ""
    finish_reason: str | None = None
    stream_ended = False
    saw_any_event = False
    got_any_content = False
    emitted_prose = ""
    block_count = 0

    def find_block(kind: str) -> dict | None:
        return next((block for block in blocks if block["kind"] == kind), None)

    def new_block(kind: str) -> dict:
        nonlocal next_index
        block = {"index": next_index, "kind": kind, "text": ""}
        next_index += 1
        blocks.append(block)
        return block

    pending: list[dict] = []

    async for line in lines:
        if stream_ended:
            break
        trimmed = line.strip()
        if trimmed == "":
            if current_event != "":
                event = parse_trae_sse_line(current_event, current_data)
                current_event = ""
                current_data = ""
                saw_any_event = True
                name = event.get("event")
                if name == "output":
                    delta_text = event.get("response")
                    reasoning = event.get("reasoningContent")
                    calls = event.get("toolCalls")
                    if isinstance(delta_text, str) and delta_text != "":
                        got_any_content = True
                        block = find_block("text")
                        if block is None:
                            block = new_block("text")
                            pending.append({"type": "block-start", "index": block["index"], "blockType": "text"})
                        block["text"] += delta_text
                        emitted_prose += delta_text
                        pending.append({"type": "text-delta", "index": block["index"], "text": delta_text})
                    if isinstance(reasoning, str) and reasoning != "":
                        block = find_block("reasoning")
                        if block is None:
                            block = new_block("reasoning")
                            pending.append({"type": "block-start", "index": block["index"], "blockType": "reasoning"})
                        block["text"] += reasoning
                        pending.append({"type": "reasoning-delta", "index": block["index"], "text": reasoning})
                    if isinstance(calls, list) and calls:
                        for call in calls:
                            if not isinstance(call, dict):
                                continue
                            wire_index = call.get("index") if isinstance(call.get("index"), int) else 0
                            call_id = call.get("id")
                            if isinstance(call_id, str) and call_id != "":
                                tool_ids[wire_index] = call_id
                            resolved_id = tool_ids.get(wire_index, f"call_{wire_index}")
                            block = tool_calls.get(wire_index)
                            if block is None:
                                block = {"index": next_index, "text": "", "callId": resolved_id, "announced": False,
                                         "name": None}
                                next_index += 1
                                tool_calls[wire_index] = block
                            block["callId"] = resolved_id
                            fn = call.get("function") if isinstance(call.get("function"), dict) else None
                            if fn is not None and isinstance(fn.get("name"), str) and fn["name"] != "":
                                block["name"] = fn["name"]
                            fragment = fn.get("arguments") if fn is not None and isinstance(fn.get("arguments"), str) else ""
                            block["text"] += fragment
                            # ⚠️ 名称为空前不发射任何 chunk（空名 tool-call 会污染会话）。
                            if not block["announced"]:
                                if not has_usable_tool_name(block.get("name")):
                                    continue
                                block["announced"] = True
                                tool_order.append(block["index"])
                                pending.append({"type": "block-start", "index": block["index"],
                                                "blockType": "tool-call"})
                                pending.append({"type": "tool-call-delta", "index": block["index"], "id": resolved_id,
                                                "name": block["name"], "argumentsDelta": block["text"]})
                                continue
                            chunk = {"type": "tool-call-delta", "index": block["index"], "id": resolved_id,
                                     "argumentsDelta": fragment}
                            if block.get("name") is not None:
                                chunk["name"] = block["name"]
                            pending.append(chunk)
                elif name == "token_usage":
                    usage = event.get("usage")
                    if isinstance(usage, dict):
                        pending.append({"type": "usage", "usage": _map_usage(usage)})
                elif name == "done":
                    if isinstance(event.get("finishReason"), str):
                        finish_reason = event["finishReason"]
                    stream_ended = True
                elif name == "error":
                    code = event.get("errorCode")
                    message = event.get("errorMessage")
                    if code is not None and message is not None:
                        raise UpstreamError(trae_stream_error_message(code, message, model),
                                            CODE["quota"] if code in (1005, 4008) else CODE["server"],
                                            status=200, streamCode=code)
                while pending:
                    yield pending.pop(0)
            continue
        if trimmed.startswith("event:"):
            current_event = trimmed[6:].strip()
        elif trimmed.startswith("data:"):
            # ⚠️ SOLO 的 data 可能跨行拼接（这里不 strip，与 TS 的 slice(5) 同）。
            current_data += trimmed[5:]

    if not saw_any_event:
        error = UpstreamError("trae: upstream returned no events (empty response before first model event)",
                              CODE["transport"])
        error.noEvents = True  # type: ignore[attr-defined]
        raise error

    # ── 收尾：关闭各块 ──
    for index in tool_order:
        block = next((candidate for candidate in tool_calls.values() if candidate["index"] == index), None)
        if block is None or not has_usable_tool_name(block.get("name")):
            continue
        block_count += 1
        arguments = block["text"] if is_truncated_arguments(block["text"]) else normalize_tool_arguments(block["text"])
        yield {"type": "block-end", "index": index,
               "block": {"type": "tool-call", "id": block.get("callId") or "", "name": block["name"],
                         "arguments": arguments}}

    text_block = find_block("text")
    if text_block is not None:
        if text_block["text"] != "":
            block_count += 1
            yield {"type": "block-end", "index": text_block["index"],
                   "block": {"type": "text", "text": text_block["text"]}}
    reasoning_block = find_block("reasoning")
    if reasoning_block is not None and reasoning_block["text"].strip() != "":
        block_count += 1
        yield {"type": "block-end", "index": reasoning_block["index"],
               "block": {"type": "reasoning", "text": reasoning_block["text"]}}

    args_truncated = any(is_truncated_arguments(block["text"]) for block in tool_calls.values())
    dropped_unnamed = any(not block["announced"] for block in tool_calls.values())
    prose_cut = (finish_reason == "stop" and not tool_order
                 and is_prose_truncated_by_stop_string(emitted_prose))

    if (finish_reason == "length" or (finish_reason is None and tool_order) or args_truncated
            or prose_cut or (dropped_unnamed and not tool_order)):
        kind = "max-tokens"
    elif finish_reason == "tool_calls" or tool_order:
        kind = "tool-calls"
    else:
        kind = "stop"

    if kind == "stop" and block_count == 0:
        # 零内容块 + stop 属于 DSH 的 EMPTY_RESPONSE 契约禁止的静默结束。
        yield {"type": "finish", "reason": {
            "kind": "error",
            "failure": {"message": "model returned a completed response with no content", "code": CODE["empty"]}}}
        return
    yield {"type": "finish", "reason": {"kind": kind}}


# ── 推理（trae-adapter.ts 的 stream / send） ──────────────────────────────

def _catalog_model(catalog: Any, model_id: str) -> dict | None:
    if not isinstance(catalog, dict):
        return None
    for row in catalog.get("models") or []:
        if isinstance(row, dict) and row.get("id") == model_id:
            return row
    return None


def _channel_for(model_id: str, catalog: Any) -> str:
    """模型只在**列出它的通道**里可调用；查不到回退默认通道。"""
    row = _catalog_model(catalog, model_id)
    channel = row.get("channel") if row else None
    if isinstance(channel, str) and channel != "":
        return channel
    return FUNCTION


def _max_mode_for(model_id: str, catalog: Any) -> bool:
    """Max 模式三条件：产品开关（默认开）+ 远端 ``max_mode`` + 白名单。"""
    if not resolve_max_mode_flag():
        return False
    row = _catalog_model(catalog, model_id)
    if row is None or row.get("maxMode") is not True:
        return False
    whitelist = resolve_max_mode_models()
    if whitelist and "*" not in whitelist:
        return model_id in whitelist
    return True


def build_solo_payload(body: dict, model_id: str, catalog: Any) -> dict:
    """把调用方给的 OpenAI 请求体转成 SOLO 请求体（含输出额度收敛与 Max 模式）。"""
    openai_body = dict(body)
    max_tokens = clamp_trae_max_tokens(openai_body.get("max_tokens"))
    if max_tokens is not None:
        openai_body["max_tokens"] = max_tokens
    payload = transform_to_solo_body(openai_body, None, _channel_for(model_id, catalog))
    # Max 模式：必须在 clamp 之后成套覆盖（否则输出预算被安全线压掉、失去意义）。
    if _max_mode_for(model_id, catalog):
        row = _catalog_model(catalog, model_id) or {}
        payload.update(trae_max_mode_fields(row.get("maxContextWindow"), row.get("maxModeOutputTokens")))
    return payload


async def _send_chat(client: httpx.AsyncClient, credential: dict, data: bytes):
    """发一次 chat 请求；网络失败映射为可重试的 TRANSPORT。"""
    global _SEND_COUNT
    _SEND_COUNT += 1
    headers = trae_solo_headers(credential, True, _machine_id_generation())
    url = f"{TRAE_AGENT_HOST}{TRAE_CHAT_PATH}"
    try:
        return await client.send(client.build_request("POST", url, headers=headers, content=data), stream=True)
    except httpx.HTTPError as error:
        raise UpstreamError(f"trae: transport error: {error}", CODE["transport"])


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """POST 一轮 SOLO 对话并把**自定义 SSE** 转成本项目内部 chunk。

    - 产出：``text-delta`` / ``reasoning-delta`` / ``tool-call-delta`` / ``usage`` /
      ``finish``（另有 ``block-start`` / ``block-end``，与内部块协议同一形态）；
    - 401/403 静默续期一次后原样重发；
    - HTTP 200 却一个事件都没收到 → 同账号重试一次，仍失败报 TRANSPORT；
    - 流内 ``event:error`` 直接抛（1005/4008 → 额度码，其余 → 服务端码）。
    """
    model_id = str(body.get("model") or "")
    payload = build_solo_payload(body, model_id, catalog)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    client = await get_client()

    refreshed = False
    empty_retried = False
    while True:
        response = await _send_chat(client, credential, data)
        try:
            if response.status_code in (401, 403) and not refreshed:
                refreshed = True
                await response.aread()
                await response.aclose()
                fresh = await refresh_credential(credential)
                credential = fresh
                if on_refresh is not None:
                    on_refresh(fresh)
                continue
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                kind = classify_trae_error(response.status_code, text)
                raise UpstreamError(f"trae: {error_detail(text)[:300]}", error_code_for(kind, response.status_code),
                                    status=response.status_code, kind=kind)
            head = await read_head(response.aiter_bytes(), 4096, TRAE_STREAM_TIMEOUT_S)
            shape = sniff_body(head.text)
            if shape == "empty":
                # TS 的等价路径：HTTP 200 却连一个字节都没有 → 「upstream returned no events」，
                # 与「有响应体但零事件」同属**可重试的瞬时故障**（同账号重试一次）。
                error = UpstreamError("trae: upstream returned no events (empty response body)",
                                      CODE["transport"])
                error.noEvents = True  # type: ignore[attr-defined]
                if not empty_retried:
                    empty_retried = True
                    continue
                raise error
            if shape != "sse":
                text = (await _read_remainder(head)).decode("utf-8", "replace")
                raise UpstreamError(f"trae: unexpected non-stream response: {text[:200]}", CODE["server"])
            try:
                async for chunk in _consume_solo(_iter_lines(_replay(head)), model_id):
                    yield chunk
                return
            except UpstreamError as error:
                # ① 空响应（HTTP 200 但一个事件都没发）→ 同账号重试一次。
                if getattr(error, "noEvents", False) and not empty_retried:
                    empty_retried = True
                    continue
                raise
        finally:
            try:
                await response.aclose()
            except Exception:  # noqa: BLE001
                pass
