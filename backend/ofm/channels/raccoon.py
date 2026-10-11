"""Raccoon Work（商汤小浣熊）渠道。

移植自原版 channel-pack 的 ``raccoon.ts`` / ``raccoon-oauth.ts`` / ``raccoon-auth.ts`` /
``raccoon-adapter.ts`` / ``raccoon-product.ts`` / ``raccoon-login-page.ts`` /
``raccoon-qr.ts``（以及共享层 ``openai-compat.ts`` 的语义）。SSE 解析走
``..stream.read_stream``（等价原版 ``sse.ts`` 的 ``consumeOpenAiSse``），故本模块
只负责「端点 + 鉴权头 + 请求体 + 登录流程」。

## 与其它渠道的关键差异：**交互式登录**，没有一次性 ``run_login``

Raccoon 是**微信扫码 / 短信交互式登录**（官方桌面端的 ``office-raccoon://auth/callback``
自定义协议回调宿主侧收不到，且 ``/code/authorize`` 页的回调地址写死、改不成 localhost），
故本模块**只**实现「分步登录」：

1. ``async def start_login()`` —— 起一次登录会话：本地随机生成 ``qrcode_code``，
   把 ``https://xiaohuanxiong.com/login/mp?code=<32位hex>&appname=商汤小浣熊官网``
   渲染成二维码（本文件内置的零依赖 QR 编码器，移植自 ``raccoon-qr.ts``），返回
   ``{status: "awaiting-code", hint, qr(dataURL), needPhone, path}``。**立即返回**，
   同时在后台起一个 2 秒间隔的轮询任务（``login_with_qrcode_code``）。
2. ``async def submit_login(payload)`` —— 处理下一步：
   - ``payload`` 里给 11 位手机号（``phone``/``code`` 皆可）→ ``POST …/send_sms``
     下发短信验证码，返回 ``{status:"awaiting-code", needPhone:False, hint}``；
   - 会话已有手机号时给验证码 → ``POST …/login_with_sms`` → 返回含 ``access_token``
     的凭据 dict（管理器据此注册账号）；
   - 空 ``payload``（或显式 ``action="poll"``）→ 等扫码结果（轮询窗口见
     ``QR_WAIT_SLICE_S``），完成则返回凭据，未完成则再回 ``awaiting-code``；
   - 任意单步失败**不终止**会话，把原因放进 ``hint`` 让用户就地重试（与
     ``raccoon-login-page.ts`` 的语义一致）。

## 三个必须记住的坑（来自 ``raccoon.ts`` 的原始注释）

1. **扫码 ``code`` 由客户端本地随机生成**（16 字节 → 32 位小写 hex），实测服务端
   接受任意自造 code 并置为 ``pending``，故完全绕开那条收不到的自定义协议回调。
   ``status`` 取值只有 ``pending`` / ``logging`` / ``canceled`` / ``success``；
   ``canceled`` 时要**换一个新 code**（否则用户卡死）。
2. **手机号必须 AES-128-CFB 加密**（密钥 ``senseraccoon2023``，16 字节 ⇒ AES-128；
   输出 ``Base64(iv(16B) ‖ ciphertext)``），否则 ``send_sms`` 回
   ``100003 params_encryted_error``；且 ``send_sms`` 要求先过阿里云滑块拿到
   ``captcha_param``，否则 ``100006 captcha_verify_error``。
3. **每日 300 积分没有端点**（服务端按日自动发放 ``daily_grant``），不要实现成
   签到。本文件只在登录成功后**尽力**领取一次性的「桌面端登录奖励」
   （``POST …/desktop/v1/login/points/grant``，幂等，已领过返回 ``granted:false``）。

## 推理

``POST https://xiaohuanxiong.com/api/web/llm/v2/chat/completions``，标准 OpenAI
Chat Completions + 标准 SSE（``chat.completion.chunk`` + ``data: [DONE]``）。
思考字段是 ``delta.reasoning_content``（``read_stream`` 亦认 ``reasoning``），
工具调用是 ``delta.tool_calls``（按 ``index`` 合并）。

⚠️ **思考档位只有「开 / 关」两态**，唯一有效通道是 ``extra_body.thinking.type``
（枚举 ``adaptive`` / ``enabled`` / ``disabled``）。``reasoning_effort`` 虽被服务端
接受但**实测不产生任何可观测效果**；``extra_body`` **之外的** ``thinking`` 会被忽略。
故：档位为 ``off`` → ``{type:'disabled'}``，其余（含 ``on``）→ ``{type:'enabled'}``，
**不传档位时不下发该字段**（保持服务端默认 = 开）。
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import re
import secrets
import time
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import finish_reason, read_stream

CHANNEL_ID = "raccoon"

# ── 端点与常量（raccoon.ts / raccoon-product.ts 的 RACCOON） ────────────────

API_BASE = "https://xiaohuanxiong.com"

AUTH_PREFIX = "/api/web/auth/v1"
LLM_PREFIX = "/api/web/llm/v2"
POINTS_PREFIX = "/api/web/points/v1"
DESKTOP_PREFIX = "/api/web/desktop/v1"

QR_LOGIN_PATH = "/login_with_qrcode_code"
SEND_SMS_PATH = "/send_sms"
LOGIN_SMS_PATH = "/login_with_sms"
LOGIN_AUTH_CODE_PATH = "/login_with_authorization_code"
REFRESH_PATH = "/refresh"
USER_INFO_PATH = "/user_info"

CHAT_PATH = f"{LLM_PREFIX}/chat/completions"
MODEL_CATALOG_PATH = f"{LLM_PREFIX}/model_catalog"
LOGIN_REWARD_PATH = f"{DESKTOP_PREFIX}/login/points/grant"

#: 二维码承载的公开登录页（服务端 `buildQrImageUrl` 的形态）。
QR_LOGIN_PAGE_PATH = "/login/mp"
QR_LOGIN_PAGE_APPNAME = "商汤小浣熊官网"

#: 产品配置（raccoon-product.ts 的 RACCOON）。
DISPLAY_NAME = "Raccoon (商汤)"
USER_AGENT = "Raccoon Work/1.0.35 (Windows)"
CLIENT_PLATFORM = "desktop-windows"
CLIENT_VERSION = "v1.0.35"
DEFAULT_CREDENTIAL_REF = "RACCOON_ACCESS_TOKEN"

#: 手机号传输层加密密钥。⚠️ 公开常量（客户端硬编码在前端 bundle 里），
#: 只用于防止手机号明文出现在日志/代理里，**不是安全边界**。
PHONE_CIPHER_SECRET = "senseraccoon2023"

#: 阿里云滑块验证码配置（短信登录必需；渲染层模块 37907 的 `q3` / `$j`）。
ALIYUN_CAPTCHA_SCENE_ID = "1pkmy0x3"
ALIYUN_CAPTCHA_PREFIX = "hk1r5l"

#: 请求超时（秒）。原版 ``RACCOON_REQUEST_TIMEOUT_MS = 60_000``。
REQUEST_TIMEOUT_S = 60.0
#: 模型目录请求超时（raccoon-auth.ts 的 ``AbortSignal.timeout(20_000)``）。
CATALOG_TIMEOUT_S = 20.0
#: 推理流读取超时（秒）。
STREAM_TIMEOUT_S = 600.0

#: 扫码轮询间隔（秒）。原版 ``RACCOON_QR_POLL_INTERVAL_MS = 2_000``。
POLL_INTERVAL_S = 2.0
#: 扫码登录整体超时（秒）。原版 ``RACCOON_LOGIN_TIMEOUT_MS = 5 * 60 * 1000``。
LOGIN_TIMEOUT_S = 5 * 60.0
#: 单次 ``submit_login`` 等扫码结果的窗口（秒）。
#:
#: ⚠️ 这是本移植的**取舍**，不是原版常量：原版由登录页每 2 秒自动轮询，
#: 而本项目的渠道路由只通过 ``submit_login`` 把凭据交回管理器（管理器没有
#: 「后台完成」的回调通道），故这里既在后台持续轮询、又让每次 ``submit``
#: 最多等这么久，用户点一次「提交」通常就能拿到结果；超过窗口仍返回
#: ``awaiting-code``，前端再点一次即可（进度由后台任务保留）。
QR_WAIT_SLICE_S = 25.0

#: 终态（凭据 / 错误）交付宽限期（秒）。
#:
#: ⚠️ 终态由**后台**轮询任务落定，而交付要等用户点「提交」；这中间必须留一段
#: 时间让那份结果还活着，否则用户会「点了提交却什么都没发生」（会话已被清掉，
#: 于是又开了一个新会话）。
DELIVERY_GRACE_S = 120.0

#: 扫码状态机的状态值（RACCOON_QR_STATUS）。
QR_STATUS_PENDING = "pending"
QR_STATUS_LOGGING = "logging"
QR_STATUS_CANCELED = "canceled"
QR_STATUS_SUCCESS = "success"

#: 续期提前窗口（秒）。照抄官方 ``scheduleAuth.js`` 的 ``TOKEN_REFRESH_WINDOW_SECONDS``
#: （access_token 寿命约 3 小时，提前 5 分钟刷新）。
TOKEN_REFRESH_WINDOW_S = 300

#: 业务错误码（raccoon-oauth.ts）。
CODE_PARAMS_ENCRYPTED_ERROR = 100003
CODE_CAPTCHA_VERIFY_ERROR = 100006
CODE_AUTH_CODE_INVALID = 200035
CODE_REFRESH_EXPIRED = 200003

#: 登录奖励（raccoon-credits.ts）。
LOGIN_REWARD_POINTS = 3000
LOGIN_REWARD_EVENT_NAME = "桌面端登录奖励"

#: 手机号判定（raccoon-login-page.ts 的 ``/^1[3-9]\d{9}$/``）。
MOBILE_RE = re.compile(r"^1[3-9]\d{9}$")
_NUMBER_TEXT = re.compile(r"^-?\d+(\.\d+)?$")

# ── 模型（raccoon-product.ts 的 RACCOON_FALLBACK_MODELS） ──────────────────

#: 兜底模型目录（6 个 ``visible:true`` 模型）。
#:
#: 顺序**照抄远端返回顺序**，展示名由 ``raccoonDisplayName`` 的输出形态固化
#: （`` · x倍率`` / `` · 免费`` / `` · x原价→x折后价``）。⚠️ 不含 ``Raccoon-Auto``
#: （那是客户端 i18n 渲染的「自动选模」入口，直接发会 404），也不含 3 个
#: ``visible:false`` 的 ``raccoon-*`` 内部模型。
FALLBACK_MODELS: list[dict] = [
    {"id": "sn-sensenova-6-8-flash", "name": "SenseNova-6.8-Flash · 免费",
     "contextWindow": 256_000, "maxOutput": 63_999, "vision": True},
    {"id": "sn-sensenova-6-8-flash-lite", "name": "SenseNova-6.8-Flash-Lite · 免费",
     "contextWindow": 256_000, "maxOutput": 63_999, "vision": True},
    {"id": "sn-glm-5-3", "name": "GLM-5-3 · x0.75",
     "contextWindow": 1_000_000, "maxOutput": 100_000, "vision": True},
    {"id": "sn-kimi-k3", "name": "Kimi-K3 · x1",
     "contextWindow": 1_000_000, "maxOutput": 100_000, "vision": True},
    {"id": "sn-glm-5-3-flash", "name": "GLM-5-3-Flash · x0.2→x0.1",
     "contextWindow": 1_000_000, "maxOutput": 100_000, "vision": True},
    {"id": "sn-deepseek-v4-1-flash", "name": "DeepSeek-V4.1-Flash · x0.25",
     "contextWindow": 1_000_000, "maxOutput": 100_000, "vision": True},
]

FALLBACK_INDEX: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS}
CONTEXT_WINDOWS: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS}

#: 远端 ``tags`` 缺 ``vision``、但**实测能看图**的模型（RACCOON_IMAGE_CAPABILITY_OVERRIDES）。
#: ``tags`` 是客户端「自动选模」的偏好标签，**不是**服务端能力契约。
IMAGE_CAPABILITY_OVERRIDES = frozenset({"sn-deepseek-v4-1-flash", "sn-glm-5-3-flash"})

#: 思考档位 id／展示名（raccoon-product.ts）。
EFFORT_ON = "on"
EFFORT_OFF = "off"
EFFORT_NAMES = {EFFORT_ON: "开启", EFFORT_OFF: "关闭"}
REASONING_EFFORTS = (EFFORT_ON, EFFORT_OFF)
DEFAULT_EFFORT = EFFORT_ON


# ── 纯函数：凭据与过期（raccoon.ts） ───────────────────────────────────────

def decode_jwt_exp_ms(token: Any) -> int | None:
    """解码 JWT payload 的 ``exp``，换算成**毫秒**时间戳；失败返回 None。

    ⚠️ 只解码、**不验签** —— 签名由服务端校验，我们只需要知道何时该续期。
    ⚠️ 任何解析失败都返回 None 而**不抛错**：凭据可能被手工改坏，那时应降级成
    「无过期信息」（宁可试一次），而不是让整个 provider 崩。
    """
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
    if not isinstance(payload, dict):
        return None
    exp = payload.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp) or exp <= 0:
        return None
    return int(exp * 1000)


def credential_expires_at_ms(credential: dict) -> int | None:
    """凭据过期时刻（毫秒）：``expires_at`` 优先，回退 JWT 的 ``exp``。

    ⚠️ 回退到 JWT 是**必需**的：``expires_at`` 是可选字段，老凭据可能没有它，
    只读它会让过期判定恒为 false（表现为「凭据悄悄过期、续期从不触发」）。
    """
    if not isinstance(credential, dict):
        return None
    raw = credential.get("expires_at")
    if isinstance(raw, str) and raw.strip() != "":
        try:
            parsed = float(raw.strip())
        except ValueError:
            parsed = None
        if parsed is not None and math.isfinite(parsed) and parsed > 0:
            return int(parsed)
    elif isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw) and raw > 0:
        return int(raw)
    return decode_jwt_exp_ms(credential.get("access_token"))


def is_expired(credential: dict, now_ms: int | None = None) -> bool:
    """凭据是否已过期。无任何过期信息时视为**不过期**（服务端回 401 我们会续期）。"""
    expires_at = credential_expires_at_ms(credential)
    if expires_at is None:
        return False
    now = int(time.time() * 1000) if now_ms is None else now_ms
    return expires_at <= now


def is_refreshable(credential: dict) -> bool:
    """是否可静默续期：``refresh_token`` 非空（raccoon **有** refresh 端点）。"""
    if not isinstance(credential, dict):
        return False
    token = credential.get("refresh_token")
    return isinstance(token, str) and token.strip() != ""


def needs_refresh(credential: dict, now_ms: int | None = None) -> bool:
    """是否进入续期窗口（提前 ``TOKEN_REFRESH_WINDOW_S`` 秒）。"""
    expires_at = credential_expires_at_ms(credential)
    if expires_at is None:
        return False
    now = int(time.time() * 1000) if now_ms is None else now_ms
    return expires_at - now <= TOKEN_REFRESH_WINDOW_S * 1000


def _cfb_mode(nonce: bytes):
    """构造 AES-CFB（128 位段）模式对象。

    ⚠️ cryptography 50 起把 ``modes.CFB`` 标为弃用并挪到 ``decrepit`` 命名空间
    （``cryptography.hazmat.primitives.ciphers.modes`` 里那份会在 49.0.0 后移除），
    但**算法本身不变**（CFB 段长仍是 128 位 = nonce 长度）。两个位置都试一遍，
    避免为了消一条弃用告警而把兼容性绑死在某个版本上。
    """
    try:
        from cryptography.hazmat.decrepit.ciphers import modes as decrepit_modes

        return decrepit_modes.CFB(nonce)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import modes

        return modes.CFB(nonce)


def encrypt_phone(phone: str, iv: bytes | None = None) -> str:
    """加密手机号，供 ``send_sms`` / ``login_with_sms`` 使用。

    算法照抄客户端（渲染层模块 68284 的 ``yv()``）::

        key   = UTF8("senseraccoon2023")  → 16 字节 ⇒ AES-128
        iv    = 随机 16 字节
        mode  = CFB（流密码，无填充；对齐 CryptoJS 的 NoPadding）
        输出  = Base64(iv ‖ ciphertext)

    ⚠️ 必须**显式**用 AES-128：密钥是 16 字节，按 AES-256 会因长度不足抛错。
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    key = PHONE_CIPHER_SECRET.encode("utf-8")
    nonce = iv if iv is not None else os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), _cfb_mode(nonce)).encryptor()
    body = encryptor.update(phone.encode("utf-8")) + encryptor.finalize()
    return base64.b64encode(nonce + body).decode("ascii")


def generate_qr_code() -> str:
    """扫码用的 ``qrcode_code``：32 位小写 hex（= 16 字节随机）。"""
    return secrets.token_hex(16)


def build_qr_image_url(code: str) -> str:
    """二维码承载的微信登录页 URL（公开页面，扫码后在微信内完成授权）。"""
    from urllib.parse import urlencode

    query = urlencode({"code": code, "appname": QR_LOGIN_PAGE_APPNAME})
    return f"{API_BASE}{QR_LOGIN_PAGE_PATH}?{query}"


# ── 纯函数：模型展示名（raccoon.ts 的 raccoonDisplayName） ─────────────────

def _format_multiplier(value: float) -> str:
    text = f"{value:.4f}".rstrip("0").rstrip(".")
    return text if text != "" else "0"


def raccoon_display_name(model: dict) -> str:
    """最终展示名：``GLM-5-3 · x0.75`` / ``SenseNova-6.8-Flash · 免费`` 等。

    三条规则（照抄 ``raccoonDisplayName``）：

    - 生效价 **0** → ``· 免费``（**不是** ``x0``）；
    - 有原价且原价 **严格大于**生效价 → ``· x原价→x折后价``；
    - 其余（**含 1 倍**）→ ``· x生效价``。⚠️ 1 倍也要显示 —— 省略会让用户
      分不清「它就是 1 倍」与「我们没取到倍率」。
    - 倍率非有限数/负数 → 只回名字（避免产出「模型名 · 」这种孤立分隔符）。
    """
    description = model.get("description")
    name = description if isinstance(description, str) and description != "" else str(model.get("id") or "")
    effective = model.get("effectiveMultiplier")
    if isinstance(effective, bool) or not isinstance(effective, (int, float)) \
            or not math.isfinite(effective) or effective < 0:
        return name
    if effective == 0:
        return f"{name} · 免费"
    base = model.get("baseMultiplier")
    has_base = isinstance(base, (int, float)) and not isinstance(base, bool) \
        and math.isfinite(base) and base > 0
    if has_base and base > effective:
        return f"{name} · x{_format_multiplier(float(base))}→x{_format_multiplier(float(effective))}"
    return f"{name} · x{_format_multiplier(float(effective))}"


def raccoon_supports_image(model_id: str, tags: list[str]) -> bool:
    """图片能力判定：显式白名单 ∪ 远端 tags 命中（``raccoonSupportsImage``）。"""
    if model_id in IMAGE_CAPABILITY_OVERRIDES:
        return True
    lowered = [tag.lower() for tag in tags if isinstance(tag, str)]
    return any(tag in ("vision", "image", "image-understanding") for tag in lowered)


# ── 请求头（raccoon.ts 的 raccoonHeaders / raccoon-adapter.ts 的 headers()） ──

def raccoon_headers(credential: dict, *, platform: str | None = None,
                    version: str | None = None) -> dict[str, str]:
    """业务端点请求头（照抄 ``raccoonHeaders``）。

    ``X-Client-Platform`` 对 ``desktop/v1/login/points/grant`` **必需**，
    取值必须是 ``desktop-windows`` / ``desktop-macos`` / ``desktop-linux``。
    """
    headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {credential.get('access_token') or ''}",
        # 个人账号为空串；客户端总是发送该头
        "X-Org-Code": credential.get("office_identity") or "",
        "X-Raccoon-Language": "zh",
    }
    if isinstance(platform, str) and platform != "":
        headers["X-Client-Platform"] = platform
    if isinstance(version, str) and version != "":
        headers["X-Client-Version"] = version
    device_id = credential.get("device_id")
    if isinstance(device_id, str) and device_id != "":
        headers["X-Client-Device-ID"] = device_id
    return headers


def catalog_headers(credential: dict) -> dict[str, str]:
    """模型目录请求头（``raccoon-auth.ts`` 的 ``fetchModels``：**无** platform/Content-Type）。"""
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {credential.get('access_token') or ''}",
        "X-Org-Code": credential.get("office_identity") or "",
        "X-Raccoon-Language": "zh",
    }


def chat_headers(credential: dict) -> dict[str, str]:
    """chat 请求头（照抄 ``raccoon-adapter.ts`` 的 ``headers()``）。

    ⚠️ 与原版一致：**不含** ``X-Client-Device-ID``（适配器的 chat 头是手写的六项，
    只有积分/用户信息那类控制面请求才走 ``raccoonHeaders`` 带上设备号）。
    """
    return {
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {credential.get('access_token') or ''}",
        "X-Org-Code": credential.get("office_identity") or "",
        "X-Raccoon-Language": "zh",
        "X-Client-Platform": CLIENT_PLATFORM,
    }


# ── 业务信封（raccoon-oauth.ts 的 parseEnvelope / envelopeError） ──────────

def parse_envelope(payload: Any, status: int) -> dict:
    """解析业务信封；``code == 0`` 为成功。

    ⚠️ 失败可能以 HTTP 400/401 返回，也可能 HTTP 200 + 非 0 ``code``；
    两者都要认（``code`` 缺失时用 ``status`` 顶替，>=400 才有意义）。
    """
    record = payload if isinstance(payload, dict) else {}
    raw_code = record.get("code")
    if isinstance(raw_code, bool) or not isinstance(raw_code, (int, float)):
        code = status if status >= 400 else 0
    else:
        code = int(raw_code)
    message = record.get("message") if isinstance(record.get("message"), str) else ""
    details = record.get("details") if isinstance(record.get("details"), str) else ""
    data = record.get("data")
    return {
        "code": code,
        "message": message,
        "details": details,
        "data": data if isinstance(data, dict) else None,
    }


def envelope_error(envelope: dict, fallback: str) -> str:
    """把信封里的错误拼成一条可读信息（服务端文案优先）。"""
    parts = [text for text in (envelope.get("message"), envelope.get("details")) if text]
    return " : ".join(parts) if parts else fallback


async def post_json(url: str, body: dict, *, headers: dict[str, str] | None = None,
                    timeout_s: float = REQUEST_TIMEOUT_S) -> tuple[dict, int]:
    """发一次 JSON POST 并解析信封（对应 ``postJson``）。"""
    client = await get_client()
    try:
        response = await client.post(
            url,
            headers={"Content-Type": "application/json", **(headers or {})},
            content=json.dumps(body, ensure_ascii=False),
            timeout=timeout_s,
        )
    except httpx.HTTPError as error:
        reason = str(error) or error.__class__.__name__
        raise UpstreamError(f"raccoon: 请求失败：{reason}", CODE["transport"])
    try:
        payload: Any = response.json()
    except ValueError:
        raise UpstreamError(f"raccoon: 响应不是 JSON（HTTP {response.status_code}）", CODE["server"],
                            status=response.status_code)
    return parse_envelope(payload, response.status_code), response.status_code


async def get_json(url: str, headers: dict[str, str], *, timeout_s: float = REQUEST_TIMEOUT_S) -> dict | None:
    """发一次 JSON GET；非 2xx 或响应畸形返回 None（对应适配器的 Optional 语义）。"""
    client = await get_client()
    try:
        response = await client.get(url, headers=headers, timeout=timeout_s)
    except httpx.HTTPError as error:
        reason = str(error) or error.__class__.__name__
        raise UpstreamError(f"raccoon: GET {url} 网络失败：{reason}", CODE["transport"])
    return parse_envelope(response.json() if _is_json(response) else None, response.status_code) \
        if response.status_code < 400 else None


def _is_json(response: httpx.Response) -> bool:
    try:
        response.json()
        return True
    except ValueError:
        return False


# ── 二维码（raccoon-qr.ts 的移植：零依赖、byte 模式、纠错等级 M、版本 1–10） ──
#
# 为什么要自己实现：本仓库**没有任何 QR 依赖**，而登录页需要把
# ``https://…/login/mp?code=<32位hex>&appname=…``（约 100 字节）渲染成二维码。
# 宿主侧生成、字面量固定（会话内只在 ``canceled`` 时换一次），故直接产出
# SVG 文本并包成 ``data:image/svg+xml;base64,…`` —— 前端 ``<img src>`` 直接可用，
# 不需要任何浏览器端 QR 逻辑（消除「两份实现漂移」的风险）。

#: 各版本（1–10）纠错等级 M 的数据码字总数。
_QR_DATA_CODEWORDS = (0, 16, 28, 44, 64, 86, 108, 124, 154, 182, 216)
#: 各版本（1–10）纠错等级 M 的块结构：``(每块纠错码字数, ((块数, 每块数据码字数), …))``。
_QR_EC_BLOCKS_M: tuple = (
    None,
    (10, ((1, 16),)),
    (16, ((1, 28),)),
    (26, ((1, 44),)),
    (18, ((2, 32),)),
    (24, ((2, 43),)),
    (16, ((4, 27),)),
    (18, ((4, 31),)),
    (22, ((2, 38), (2, 39))),
    (22, ((3, 36), (2, 37))),
    (26, ((4, 43), (1, 44))),
)

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf() -> None:  # 本原多项式 0x11D
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av == 0:
            continue
        for j, bv in enumerate(b):
            out[i + j] ^= _gf_mul(av, bv)
    return out


def _rs_generator_poly(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        poly = _poly_mul(poly, [1, _GF_EXP[i]])
    return poly


def _rs_encode(data: list[int], ec_count: int) -> list[int]:
    gen = _rs_generator_poly(ec_count)
    buf = list(data) + [0] * ec_count
    for i in range(len(data)):
        coef = buf[i]
        if coef == 0:
            continue
        for j, gv in enumerate(gen):
            buf[i + j] ^= _gf_mul(gv, coef)
    return buf[len(data):]


def _qr_pick_version(byte_length: int) -> int | None:
    """选能容纳 ``byte_length`` 字节的最小版本；都装不下返回 None。"""
    for version in range(1, 11):
        capacity_bits = _QR_DATA_CODEWORDS[version] * 8
        overhead_bits = 4 + (8 if version <= 9 else 16)  # 模式指示符 + 字符计数
        if overhead_bits + byte_length * 8 <= capacity_bits:
            return version
    return None


def _qr_build_codewords(data: bytes, version: int) -> list[int]:
    blocks = _QR_EC_BLOCKS_M[version]
    if blocks is None:
        raise ValueError(f"raccoon: 不支持的二维码版本 {version}")
    ec_per_block, groups = blocks
    capacity_bits = _QR_DATA_CODEWORDS[version] * 8

    bits: list[int] = []

    def push_bits(value: int, length: int) -> None:
        for shift in range(length - 1, -1, -1):
            bits.append((value >> shift) & 1)

    push_bits(0b0100, 4)  # byte 模式
    push_bits(len(data), 8 if version <= 9 else 16)
    for byte in data:
        push_bits(byte, 8)
    push_bits(0, min(4, capacity_bits - len(bits)))  # 终止符最多 4 位
    while len(bits) % 8 != 0:
        bits.append(0)
    pad = (0xEC, 0x11)
    index = 0
    while len(bits) < capacity_bits:
        push_bits(pad[index % 2], 8)
        index += 1

    data_codewords: list[int] = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data_codewords.append(byte)

    data_blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    offset = 0
    for count, per_block in groups:
        for _ in range(count):
            block = data_codewords[offset:offset + per_block]
            offset += per_block
            data_blocks.append(block)
            ec_blocks.append(_rs_encode(block, ec_per_block))

    result: list[int] = []
    max_len = max(len(block) for block in data_blocks)
    for i in range(max_len):
        for block in data_blocks:
            if i < len(block):
                result.append(block[i])
    for i in range(ec_per_block):
        for block in ec_blocks:
            result.append(block[i])
    return result


def _qr_alignment_positions(version: int, size: int) -> list[int]:
    if version == 1:
        return []
    num_align = version // 7 + 2
    step = -(-(version * 4 + 4) // (num_align * 2 - 2)) * 2  # ceil(…)*2
    result = [6]
    pos = size - 7
    while len(result) < num_align:
        result.insert(1, pos)
        pos -= step
    return result


def _qr_draw_finder(modules: list[list[bool]], is_function: list[list[bool]], size: int,
                    x: int, y: int) -> None:
    for dy in range(-4, 5):
        for dx in range(-4, 5):
            xx, yy = x + dx, y + dy
            if xx < 0 or xx >= size or yy < 0 or yy >= size:
                continue
            dist = max(abs(dx), abs(dy))
            dark = dist != 2 and dist != 4  # 4 = 分隔符、2 = 内圈（浅色）
            modules[yy][xx] = dark
            is_function[yy][xx] = True


def _qr_draw_alignment(modules: list[list[bool]], is_function: list[list[bool]], x: int, y: int) -> None:
    for dy in range(-2, 3):
        for dx in range(-2, 3):
            dark = max(abs(dx), abs(dy)) != 1
            modules[y + dy][x + dx] = dark
            is_function[y + dy][x + dx] = True


def _qr_draw_format_bits(modules: list[list[bool]], is_function: list[list[bool]], size: int,
                         mask: int) -> None:
    """写入格式信息（纠错等级 M 的 ``formatBits`` 是 ``0b00``），两份拷贝。"""
    data = (0b00 << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    bits = ((data << 10) | rem) ^ 0x5412

    def put(x: int, y: int, dark: bool) -> None:
        modules[y][x] = dark
        is_function[y][x] = True

    def bit(i: int) -> bool:
        return ((bits >> i) & 1) == 1

    for i in range(6):
        put(8, i, bit(i))
    put(8, 7, bit(6))
    put(8, 8, bit(7))
    put(7, 8, bit(8))
    for i in range(9, 15):
        put(14 - i, 8, bit(i))
    # 第二份：第 8 行右侧 8 列 + 第 8 列底部 7 行（size-7 .. size-1）
    for i in range(8):
        put(size - 1 - i, 8, bit(i))
    for i in range(8, 15):
        put(8, size - 7 + (i - 8), bit(i))
    put(8, size - 8, True)  # 固定的深色模块


def _qr_draw_function_patterns(modules: list[list[bool]], is_function: list[list[bool]],
                               size: int, version: int) -> None:
    for i in range(size):
        dark = i % 2 == 0
        modules[6][i] = dark
        is_function[6][i] = True
        modules[i][6] = dark
        is_function[i][6] = True

    _qr_draw_finder(modules, is_function, size, 3, 3)
    _qr_draw_finder(modules, is_function, size, size - 4, 3)
    _qr_draw_finder(modules, is_function, size, 3, size - 4)

    positions = _qr_alignment_positions(version, size)
    n = len(positions)
    for i in range(n):
        for j in range(n):
            if (i == 0 and j == 0) or (i == 0 and j == n - 1) or (i == n - 1 and j == 0):
                continue
            _qr_draw_alignment(modules, is_function, positions[i], positions[j])

    _qr_draw_format_bits(modules, is_function, size, 0)

    if version >= 7:
        rem = version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = (version << 12) | rem
        for i in range(18):
            dark = ((bits >> i) & 1) == 1
            a = size - 11 + (i % 3)
            b = i // 3
            modules[b][a] = dark
            is_function[b][a] = True
            modules[a][b] = dark
            is_function[a][b] = True


def _qr_draw_codewords(modules: list[list[bool]], is_function: list[list[bool]], size: int,
                       codewords: list[int]) -> None:
    i = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5  # 跳过 timing 列
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if is_function[y][x] is not True and i < len(codewords) * 8:
                    byte = codewords[i >> 3]
                    modules[y][x] = ((byte >> (7 - (i & 7))) & 1) == 1
                    i += 1
        right -= 2


def _qr_apply_mask(modules: list[list[bool]], is_function: list[list[bool]], size: int, mask: int) -> None:
    for y in range(size):
        for x in range(size):
            if is_function[y][x] is True:
                continue
            if mask == 0:
                invert = (x + y) % 2 == 0
            elif mask == 1:
                invert = y % 2 == 0
            elif mask == 2:
                invert = x % 3 == 0
            elif mask == 3:
                invert = (x + y) % 3 == 0
            elif mask == 4:
                invert = (y // 2 + x // 3) % 2 == 0
            elif mask == 5:
                invert = ((x * y) % 2) + ((x * y) % 3) == 0
            elif mask == 6:
                invert = (((x * y) % 2) + ((x * y) % 3)) % 2 == 0
            else:
                invert = (((x + y) % 2) + ((x * y) % 3)) % 2 == 0
            if invert:
                modules[y][x] = not modules[y][x]


def _qr_penalty_for_line(line: list[bool], size: int, n1: int, n3: int) -> int:
    result = 0
    run = 1
    for i in range(1, size):
        if line[i] == line[i - 1]:
            run += 1
        else:
            if run >= 5:
                result += n1 + (run - 5)
            run = 1
    if run >= 5:
        result += n1 + (run - 5)

    pattern_a = [True, False, True, True, True, False, True, False, False, False, False]
    pattern_b = [False, False, False, False, True, False, True, True, True, False, True]
    for i in range(0, size - 10):
        if line[i:i + 11] == pattern_a:
            result += n3
        if line[i:i + 11] == pattern_b:
            result += n3
    return result


def _qr_compute_penalty(modules: list[list[bool]], size: int) -> int:
    n1, n2, n3, n4 = 3, 3, 40, 10
    result = 0
    for y in range(size):
        result += _qr_penalty_for_line(modules[y], size, n1, n3)
    for x in range(size):
        column = [modules[y][x] for y in range(size)]
        result += _qr_penalty_for_line(column, size, n1, n3)
    for y in range(size - 1):
        for x in range(size - 1):
            cell = modules[y][x]
            if cell == modules[y][x + 1] and cell == modules[y + 1][x] and cell == modules[y + 1][x + 1]:
                result += n2
    dark = sum(1 for row in modules for cell in row if cell)
    total = size * size
    k = -(-abs(dark * 20 - total * 10) // total) - 1
    result += max(0, k) * n4
    return result


def build_qr_matrix(text: str, *, mask: int | None = None) -> tuple[int, list[list[bool]]]:
    """生成 QR 模块矩阵（byte 模式 + 纠错等级 M + 版本 1–10）。

    ⚠️ 超出容量（213 字节）时**抛错**，由调用方缩短内容，而不是静默产出扫不出来的坏码。
    """
    data = text.encode("utf-8")
    version = _qr_pick_version(len(data))
    if version is None:
        raise ValueError(f"raccoon: 二维码内容过长（{len(data)} 字节，上限 213 字节），请缩短内容")
    size = version * 4 + 17
    modules = [[False] * size for _ in range(size)]
    is_function = [[False] * size for _ in range(size)]

    _qr_draw_function_patterns(modules, is_function, size, version)
    _qr_draw_codewords(modules, is_function, size, _qr_build_codewords(data, version))

    if mask is not None:
        best_mask = mask
    else:
        best_mask = 0
        best_penalty = math.inf
        for candidate in range(8):
            _qr_apply_mask(modules, is_function, size, candidate)
            _qr_draw_format_bits(modules, is_function, size, candidate)
            penalty = _qr_compute_penalty(modules, size)
            if penalty < best_penalty:
                best_penalty = penalty
                best_mask = candidate
            _qr_apply_mask(modules, is_function, size, candidate)  # XOR 自逆，撤销
    _qr_apply_mask(modules, is_function, size, best_mask)
    _qr_draw_format_bits(modules, is_function, size, best_mask)
    return size, modules


def render_qr_svg(text: str, *, px: int = 200, margin: int = 4,
                  dark: str = "#000000", light: str = "#ffffff") -> str:
    """把矩阵渲染成内联 SVG（用 SVG 而非位图：页面直接插进 DOM，任意缩放都清晰）。"""
    size, modules = build_qr_matrix(text)
    dim = size + margin * 2
    segments: list[str] = []
    for y in range(size):
        for x in range(size):
            if modules[y][x]:
                segments.append(f"M{x + margin},{y + margin}h1v1h-1z")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{px}" height="{px}" '
        f'viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges" role="img">'
        f'<rect width="{dim}" height="{dim}" fill="{light}"/>'
        f'<path d="{"".join(segments)}" fill="{dark}"/></svg>'
    )


def qr_data_url(text: str, *, px: int = 200) -> str:
    """二维码 → ``data:image/svg+xml;base64,…``（前端 ``<img src>`` 直接可用）。"""
    svg = render_qr_svg(text, px=px)
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")


# ── 登录（raccoon-oauth.ts + raccoon-login-page.ts 的对外契约） ─────────────

async def poll_qr_login(code: str) -> dict:
    """轮询一次扫码登录状态（``pollRaccoonQrLogin``）。

    ⚠️ **任何异常都降级为 ``pending``**：轮询是 2 秒一次的循环，偶发失败不应中断
    整个登录流程；而把未知状态误判成 ``success`` 会让流程拿到空 token 后卡死，
    误判成 ``canceled`` 则会让正在扫码的二维码被无故刷新。
    """
    try:
        envelope, _status = await post_json(
            f"{API_BASE}{AUTH_PREFIX}{QR_LOGIN_PATH}", {"qrcode_code": code},
        )
    except UpstreamError:
        return {"status": QR_STATUS_PENDING}
    if envelope["code"] != 0 or envelope["data"] is None:
        return {"status": QR_STATUS_PENDING}
    data = envelope["data"]
    status = data.get("status") if isinstance(data.get("status"), str) else ""
    expired_at = data.get("expired_at") if isinstance(data.get("expired_at"), str) else None
    if status == QR_STATUS_CANCELED:
        return {"status": QR_STATUS_CANCELED}
    if status == QR_STATUS_LOGGING:
        return {"status": QR_STATUS_LOGGING, **({"expiredAt": expired_at} if expired_at else {})}
    if status == QR_STATUS_SUCCESS:
        access_token = data.get("access_token") if isinstance(data.get("access_token"), str) else ""
        refresh_token = data.get("refresh_token") if isinstance(data.get("refresh_token"), str) else ""
        # ⚠️ 缺 token 的 success 视为未完成：否则会产出空凭据并让流程卡死
        if access_token == "":
            return {"status": QR_STATUS_PENDING}
        exp_ms = decode_jwt_exp_ms(access_token)
        return {
            "status": QR_STATUS_SUCCESS,
            "accessToken": access_token,
            "refreshToken": refresh_token,
            **({"expiresAt": str(exp_ms)} if exp_ms is not None else {}),
        }
    return {"status": QR_STATUS_PENDING}


async def send_sms_code(phone: str, captcha_param: str) -> None:
    """下发短信验证码（``sendRaccoonSmsCode``）。

    ⚠️ 手机号必须 AES-128-CFB 加密（否则 ``100003 params_encryted_error``）。
    ⚠️ ``captcha_param`` 是阿里云滑块验证码的产物，**必需**（否则
    ``100006 captcha_verify_error``）。
    """
    envelope, _status = await post_json(
        f"{API_BASE}{AUTH_PREFIX}{SEND_SMS_PATH}",
        {"captcha_param": captcha_param, "nation_code": "86", "phone": encrypt_phone(phone)},
    )
    if envelope["code"] == 0:
        return
    if envelope["code"] == CODE_CAPTCHA_VERIFY_ERROR:
        raise UpstreamError("raccoon: 图形验证码校验失败，请重新完成滑块验证", CODE["client"])
    raise UpstreamError(f"raccoon: {envelope_error(envelope, '下发短信验证码失败')}", CODE["client"])


async def login_with_sms_code(phone: str, sms_code: str) -> dict:
    """用短信验证码登录（``loginRaccoonWithSmsCode``），返回完整凭据。"""
    envelope, _status = await post_json(
        f"{API_BASE}{AUTH_PREFIX}{LOGIN_SMS_PATH}",
        {"nation_code": "86", "phone": encrypt_phone(phone), "sms_code": sms_code},
    )
    if envelope["code"] != 0:
        raise UpstreamError(f"raccoon: {envelope_error(envelope, '短信登录失败')}", CODE["credential"])
    return _credential_from_envelope(envelope)


def _credential_from_envelope(envelope: dict) -> dict:
    """从成功信封里取出凭据；缺 ``access_token`` 时抛错（不产出半截凭据）。"""
    data = envelope.get("data") or {}
    access_token = data.get("access_token") if isinstance(data.get("access_token"), str) else ""
    refresh_token = data.get("refresh_token") if isinstance(data.get("refresh_token"), str) else ""
    if access_token == "":
        raise UpstreamError("raccoon: 登录响应缺少 access_token", CODE["server"])
    exp_ms = decode_jwt_exp_ms(access_token)
    office_identity = data.get("office_identity") if isinstance(data.get("office_identity"), str) else ""
    credential: dict = {"access_token": access_token, "refresh_token": refresh_token}
    if exp_ms is not None:
        credential["expires_at"] = str(exp_ms)
    if office_identity != "":
        credential["office_identity"] = office_identity
    return credential


async def exchange_authorization_code(authorization_code: str) -> dict:
    """用授权码换凭据（官方桌面端链路，``exchangeRaccoonAuthorizationCode``）。

    本移植**不走这条路**（收不到 ``office-raccoon://auth/callback`` 自定义协议回调），
    保留它是为了让官方链路有可单测的落点，将来支持自定义协议时可直接复用。
    """
    envelope, _status = await post_json(
        f"{API_BASE}{AUTH_PREFIX}{LOGIN_AUTH_CODE_PATH}", {"authorization_code": authorization_code},
    )
    if envelope["code"] != 0:
        if envelope["code"] == CODE_AUTH_CODE_INVALID:
            raise UpstreamError("raccoon: 授权码已失效，请重新发起登录", CODE["credential"])
        raise UpstreamError(f"raccoon: {envelope_error(envelope, '授权码登录失败')}", CODE["credential"])
    return _credential_from_envelope(envelope)


async def fetch_user_info(credential: dict) -> dict:
    """拉取用户信息（展示用）。

    ⚠️ 失败时返回**空 dict** 而不是抛错：用户信息只用于昵称展示，不该因为它失败
    而让整个登录流程失败（登录已经成功了）。
    ⚠️ ``nickname`` 取的是远端的 ``name``，而它是**服务端自动生成的默认名**
    （实测 ``RaccoonAva``），微信扫码不回传微信昵称 —— 多账号消歧要靠 ``phone``。
    """
    try:
        client = await get_client()
        response = await client.get(f"{API_BASE}{AUTH_PREFIX}{USER_INFO_PATH}",
                                    headers=raccoon_headers(credential), timeout=REQUEST_TIMEOUT_S)
        if response.status_code >= 400:
            return {}
        envelope = parse_envelope(response.json(), response.status_code)
    except Exception:  # noqa: BLE001
        return {}
    if envelope["code"] != 0 or envelope["data"] is None:
        return {}
    data = envelope["data"]

    def text(key: str) -> str:
        value = data.get(key)
        return value if isinstance(value, str) else ""

    out: dict = {}
    if text("id") != "":
        out["userId"] = text("id")
    if text("name") != "":
        out["nickname"] = text("name")
    if text("office_identity") != "":
        out["officeIdentity"] = text("office_identity")
    if text("phone") != "":
        out["phone"] = text("phone")
    return out


def build_nickname(credential: dict, fallback_id: str) -> str:
    """账号展示名（``buildRaccoonNickname``）：``RaccoonAva (1100)``。

    消歧后缀优先手机号尾 4 位（更利于辨认是哪个号），否则用户 id。
    ⚠️ 远端 ``name`` 是服务端自动生成的默认名，多个账号会重名，故必须带后缀。
    """
    nickname = credential.get("nickname").strip() if isinstance(credential.get("nickname"), str) else ""
    phone = credential.get("phone").strip() if isinstance(credential.get("phone"), str) else ""
    user_id = credential.get("user_id").strip() if isinstance(credential.get("user_id"), str) else ""
    if len(phone) >= 4:
        suffix = phone[-4:]
    elif user_id != "":
        suffix = user_id
    else:
        suffix = ""
    if nickname != "":
        if suffix != "" and suffix not in nickname:
            return f"{nickname} ({suffix})"
        return nickname
    if suffix != "":
        return f"Raccoon {suffix}"
    return fallback_id


async def enrich_credential(credential: dict) -> dict:
    """补齐用户信息（id / 昵称 / 身份 / 手机号）+ 展示名；失败不影响登录。"""
    if not (credential.get("nickname") and credential.get("user_id") and credential.get("phone")):
        info = await fetch_user_info(credential)
        merged = dict(credential)
        if info.get("userId") and not merged.get("user_id"):
            merged["user_id"] = info["userId"]
        if info.get("nickname") and not merged.get("nickname"):
            merged["nickname"] = info["nickname"]
        if info.get("officeIdentity") and not merged.get("office_identity"):
            merged["office_identity"] = info["officeIdentity"]
        if info.get("phone") and not merged.get("phone"):
            merged["phone"] = info["phone"]
        credential = merged
    credential["display_name"] = build_nickname(credential, "raccoon")
    return credential


async def claim_login_reward(credential: dict) -> dict:
    """尽力领取**一次性**「桌面端登录奖励」（3000 分，幂等）。

    ⚠️ 需要 ``X-Client-Platform`` 头（标识「来自桌面端」），缺了会被拒。
    ⚠️ **不是每日签到**：已领过返回 HTTP 200 + ``granted:false``。
    ⚠️ 失败**不抛错** —— 登录已经成功了，不能因为积分接口抖动而报错。
    """
    try:
        envelope, _status = await post_json(
            f"{API_BASE}{LOGIN_REWARD_PATH}", {},
            headers=raccoon_headers(credential, platform=CLIENT_PLATFORM, version=CLIENT_VERSION),
        )
    except UpstreamError as error:
        return {"ok": False, "message": str(error)}
    if envelope["code"] != 0:
        return {"ok": False, "message": envelope_error(envelope, "领取登录奖励失败")}
    data = envelope["data"] or {}
    return {"ok": True, "granted": data.get("granted") is True}


class _LoginSession:
    """一次交互式登录会话（**只存在于本进程内存**，不落盘）。"""

    def __init__(self, *, timeout_s: float = LOGIN_TIMEOUT_S) -> None:
        self.path = "qr"                     # qr | sms
        self.code = generate_qr_code()       # 宿主侧持有的扫码 code
        self.phone = ""                      # 发过短信后才有值
        self.need_phone = True
        self.hint = ""
        #: 与二维码对应的稳定文案（``_refresh_qr`` 重算）。
        self.base_hint = ""
        #: 一次性状态说明（如「尚未检测到扫码结果」），每次提交前重置。
        self.notice = ""
        #: **粘性**状态说明（如「二维码已失效并刷新」「验证码已下发」），
        #: 必须活到下一次真正改变状态的动作为止 —— 否则它会被紧接着的一次
        #: 「等扫码窗口超时」的提示盖掉，用户永远看不到二维码已经换过了
        #: （真实缺陷：测试里 canceled 之后只看到「尚未检测到扫码结果」）。
        self.sticky_notice = ""
        self.status = "awaiting-code"
        self.qr: str | None = None
        self.credential: dict | None = None
        self.error = ""
        self.deadline = time.monotonic() + timeout_s
        self.event = asyncio.Event()
        self.task: asyncio.Task | None = None
        #: 终态（成功凭据 / 错误）是否已交给 ``submit_login``。
        #:
        #: ⚠️ **不能用「已落定」当作「可清理」**：扫码是用户在微信里完成的，
        #: 后台轮询会先把会话置为 ``success``，而凭据只有在用户点「提交」
        #: （``submit_login``）时才交回管理器。若此时就清掉会话，那一次提交会
        #: 拿到一个全新的会话 —— 用户刚扫完的登录被静默丢弃。
        self.delivered = False
        self._refresh_qr()

    # ── 状态 ──────────────────────────────────────────────────────────────
    def settled(self) -> bool:
        return self.credential is not None or self.error != ""

    def _refresh_qr(self) -> None:
        """（重新）生成二维码 dataURL；渲染失败时退回展示登录页链接。

        ⚠️ 提示文字拆成「``base_hint``（与二维码对应的稳定文案）+ ``notice``
        （一次性状态说明）」两段再拼：每次都往 ``hint`` 前面追加会让文案随轮询
        次数无限增长（实测每次超时都接一段），用户看到一坨重复文字。
        """
        try:
            self.qr = qr_data_url(build_qr_image_url(self.code))
        except Exception:  # noqa: BLE001
            self.qr = None
        if self.qr is None:
            self.base_hint = ("请用微信打开下面的链接完成登录，或用手机号短信登录："
                              f"{build_qr_image_url(self.code)}")
        else:
            self.base_hint = ("请用微信扫描二维码完成登录（扫码后约 2 秒自动完成）；"
                              "若要改用短信登录，请在下方输入框填入 11 位手机号后提交。")
        self.hint = self.sticky_notice + self.base_hint

    def _refresh_hint(self, notice: str = "") -> str:
        """重算提示文字：``粘性说明 + 一次性说明 + 稳定文案``。

        ⚠️ 用「重算」而不是「拼接」：早期实现每次都往 ``hint`` 前面追加，
        一次登录被点几次就会攒出重复的一长串文字。
        """
        self.notice = notice
        self.hint = self.sticky_notice + self.notice + self.base_hint
        return self.hint

    def _compose_hint(self, notice: str) -> str:
        """设置**粘性**状态说明并重算提示文字。"""
        self.sticky_notice = notice
        return self._refresh_hint()

    def state(self) -> dict:
        out: dict = {
            "status": self.status,
            "hint": self.hint,
            "path": self.path,
            "needPhone": self.need_phone,
        }
        if self.path == "qr" and self.qr is not None:
            out["qr"] = self.qr
        return out

    def settle_ok(self, credential: dict) -> None:
        if self.settled():
            return
        self.credential = credential
        self.status = "ok"
        self.event.set()

    def settle_err(self, message: str) -> None:
        if self.settled():
            return
        self.error = message
        self.status = "error"
        self.event.set()

    # ── 后台轮询（原版由登录页每 2 秒调用 /raccoon/poll 完成同样的事） ─────
    async def poll_until_done(self) -> None:
        while not self.settled():
            if time.monotonic() >= self.deadline:
                self.settle_err("raccoon: 登录超时（5 分钟内未完成扫码）")
                return
            await asyncio.sleep(POLL_INTERVAL_S)
            if self.settled():
                return
            polled = await poll_qr_login(self.code)
            if polled["status"] == QR_STATUS_SUCCESS:
                credential = {
                    "access_token": polled["accessToken"],
                    "refresh_token": polled.get("refreshToken") or "",
                    **({"expires_at": polled["expiresAt"]} if polled.get("expiresAt") else {}),
                    "login_method": "qrcode",
                    "login_url": build_qr_image_url(self.code),
                }
                try:
                    credential = await _finish_login(credential)
                except UpstreamError as error:
                    self.settle_err(str(error))
                    return
                self.settle_ok(credential)
                return
            if polled["status"] == QR_STATUS_CANCELED:
                # ⚠️ 换一个新 code，让页面上的二维码重新可用（否则用户卡死）
                self.code = generate_qr_code()
                self._refresh_qr()
                self._refresh_hint()
                self._compose_hint("二维码已失效并刷新，请重新扫描。")


_SESSION: _LoginSession | None = None


def _live_session() -> _LoginSession | None:
    """取当前会话；**终态已交付**或已过交付宽限期的会话视为用完，清理掉。

    ⚠️ 判据是 ``delivered`` 而不是 ``settled()``：扫码由用户在微信里完成，
    后台轮询会先把会话置为 ``success``，而凭据要等用户点「提交」才交回管理器
    —— 见 ``_LoginSession.delivered`` 的说明。
    ⚠️ 超时（``deadline`` 到点）后仍要留 ``DELIVERY_GRACE_S`` 秒：超时是**后台**
    任务判定的，用户此刻可能正要点「提交」，立刻清掉会让那次提交开出一个全新
    会话、错误原因彻底丢失（表现为「点了提交却什么都没有发生」）。
    """
    global _SESSION
    session = _SESSION
    if session is None:
        return None
    if session.delivered or time.monotonic() >= session.deadline + DELIVERY_GRACE_S:
        _SESSION = None
        return None
    return session


async def _finish_login(credential: dict) -> dict:
    """登录收尾：补用户信息 + 计算展示名（与 ``persistLogin`` 对齐）。"""
    enriched = await enrich_credential(credential)
    reward = await claim_login_reward(enriched)
    enriched["login_reward"] = reward
    return enriched


async def start_login(*, timeout_s: float = LOGIN_TIMEOUT_S) -> dict:
    """发起一次交互式登录（微信扫码为主，短信为辅）。**立即返回**，不阻塞。

    返回形如::

        {"status": "awaiting-code", "hint": "…", "qr": "data:image/svg+xml;base64,…",
         "path": "qr", "needPhone": True}

    扫码结果由后台轮询任务（2 秒间隔、5 分钟超时）落在会话里，
    ``submit_login`` 负责把凭据交回管理器。
    """
    global _SESSION
    session = _live_session()
    # 只在「尚未落定」时复用：已落定的会话正等着 ``submit_login`` 取结果，
    # 但 ``start_login`` 的语义是「开一次新登录」，不该把凭据混进 await-state
    # 里回给前端（``manager.start_login`` 会把返回值原样拼进 loginState）。
    if session is None or session.settled():
        session = _LoginSession(timeout_s=timeout_s)
        _SESSION = session
        session.task = asyncio.create_task(session.poll_until_done())
    return session.state()


def _payload_value(payload: dict) -> str:
    for key in ("phone", "code", "value", "sms_code", "smsCode"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip() != "":
            return value.strip()
    return ""


async def _wait_for_result(session: _LoginSession, window_s: float) -> None:
    """等扫码结果落定（窗口见 ``QR_WAIT_SLICE_S``）；到点未完成就返回，会话继续。"""
    remaining = min(window_s, max(0.0, session.deadline - time.monotonic()))
    if remaining <= 0:
        session.settle_err("raccoon: 登录超时（5 分钟内未完成扫码）")
        return
    try:
        await asyncio.wait_for(session.event.wait(), timeout=remaining)
    except asyncio.TimeoutError:
        session._refresh_hint("尚未检测到扫码结果；若已在微信里完成授权，请再点一次「提交」。")


async def submit_login(payload: dict | None = None) -> dict:
    """分步登录的下一步。

    参数（``payload`` 任一字段即可，前端把同一个值同时放进 ``code`` 与 ``phone``）：

    - ``phone`` / ``code`` = 11 位手机号（``^1[3-9]\\d{9}$``）→ 下发短信验证码；
    - ``captcha_param`` = 阿里云滑块产物的 ``captchaParam``（短信登录**必需**，
      本项目前端目前不提供，故短信路径需要调用方显式给出）；
    - 会话已有手机号时，``code`` = 短信验证码 → 完成登录；
    - 空 payload / ``action="poll"`` → 等扫码结果；
    - ``path="sms"`` / ``path="qr"`` 可显式指定路径（默认扫码头）。

    返回值：

    - 含 ``access_token`` 的凭据 dict → 登录成功（管理器据此注册账号）；
    - 含 ``status`` 的 dict（``awaiting-code`` / ``error``）→ 继续渲染或报错。
    """
    session = _live_session()
    if session is None:
        await start_login()
        session = _live_session()
        if session is None:  # pragma: no cover - 理论上不可能
            return {"status": "error", "message": "raccoon: 登录会话创建失败"}
    if not isinstance(payload, dict):
        payload = {}

    # 每次提交都清掉上一次的**一次性**说明（粘性说明保留，见 sticky_notice）
    session._refresh_hint()

    action = payload.get("action") if isinstance(payload.get("action"), str) else ""
    path = payload.get("path") if isinstance(payload.get("path"), str) else ""
    value = _payload_value(payload)
    captcha = payload.get("captcha_param")
    if not isinstance(captcha, str):
        captcha = payload.get("captchaParam") if isinstance(payload.get("captchaParam"), str) else ""

    # 1) 显式要求轮询扫码（前端「提交」按钮在扫码路径下就是这一步）。
    if action in ("poll", "qr", "qrcode") or (path == "qr" and value == ""):
        await _wait_for_result(session, QR_WAIT_SLICE_S)
        return _result(session)

    # 2) 手机号 → 下发短信验证码。
    if MOBILE_RE.match(value):
        try:
            # ⚠️ 空 ``captcha_param`` 也照发：原版登录页取不到滑块产物时同样以
            # 空串调用（``const captchaParam = … : ''``），服务端会回
            # ``100006 captcha_verify_error``，我们如实把该原因转给用户。
            await send_sms_code(value, captcha)
        except UpstreamError as error:
            # 单步失败**不终止**流程（用户可能只是滑块过期/验证码输错）
            extra = ""
            # ⚠️ 判据必须是 ``str(code) in text`` 而不是 ``code in text`` ——
            # 后者是 ``int in str``，直接抛 TypeError，把「滑块验证失败」这种
            # 单步可恢复错误变成整个流程崩溃（离线烟测就撞到了）。
            text = str(error)
            if str(CODE_CAPTCHA_VERIFY_ERROR) in text or "图形验证码" in text:
                extra = "（该渠道的短信登录需要先过阿里云滑块；请改用微信扫码，或让调用方带上 captcha_param 重试）"
            session._refresh_hint(f"{text}{extra}")
            session.need_phone = True
            return _result(session)
        session.path = "sms"
        session.phone = value
        session.need_phone = False
        session._compose_hint(f"验证码已下发至 {value[:3]}****{value[-4:]}，请在下方输入框提交验证码。")
        return _result(session)

    # 3) 已有手机号 + 验证码 → 完成登录。
    if session.phone != "" and value != "":
        try:
            credential = await login_with_sms_code(session.phone, value)
        except UpstreamError as error:
            session._refresh_hint(f"{error}")
            session.need_phone = False
            return _result(session)
        credential["login_method"] = "sms"
        credential["phone"] = session.phone
        try:
            credential = await _finish_login(credential)
        except UpstreamError as error:
            session.settle_err(str(error))
            return _result(session)
        session.settle_ok(credential)
        return _result(session)

    # 4) 其余（空值/无法识别的值）→ 等扫码结果。
    await _wait_for_result(session, QR_WAIT_SLICE_S)
    return _result(session)


def _result(session: _LoginSession) -> dict:
    """把会话状态转成管理器认的形状（成功时直接回凭据 dict）。

    终态（凭据 / 错误）交付后把会话标记为 ``delivered``，下一次 ``start_login``
    会开一个干净的会话；非终态（``awaiting-code``）**不标记**，会话继续存活。
    """
    if session.credential is not None:
        session.delivered = True
        return session.credential
    if session.error != "":
        session.delivered = True
        return {"status": "error", "message": session.error}
    return session.state()


# ── 续期（raccoon-oauth.ts 的 refreshRaccoonCredential） ────────────────────

async def refresh_credential(credential: dict) -> dict:
    """用 ``refresh_token`` 换新凭据。

    ⚠️ 服务端可能**只返回新的 access_token**（不带新 refresh_token），此时必须
    **保留旧值** —— 否则续期一次就把账号变成不可续期。
    ⚠️ 服务端不返回的附加字段（昵称、身份、手机号、设备号）也要保留。
    ⚠️ 401 / 业务码 ``200003`` 表示 refresh_token 已失效 → 抛「请重新登录」且不重试。
    """
    if not is_refreshable(credential):
        raise UpstreamError("raccoon: 凭据缺少 refresh_token，请重新登录", CODE["credential"])
    envelope, status = await post_json(
        f"{API_BASE}{AUTH_PREFIX}{REFRESH_PATH}", {"refresh_token": credential.get("refresh_token")},
    )
    if status == 401 or envelope["code"] == CODE_REFRESH_EXPIRED:
        raise UpstreamError("raccoon: 登录态已过期，请重新登录", CODE["credential"], status=status)
    if envelope["code"] != 0:
        raise UpstreamError(f"raccoon: {envelope_error(envelope, '续期失败')}", CODE["credential"],
                            status=status)
    data = envelope["data"] or {}
    access_token = data.get("access_token") if isinstance(data.get("access_token"), str) else ""
    if access_token == "":
        raise UpstreamError("raccoon: 续期响应缺少 access_token", CODE["server"])
    next_refresh = data.get("refresh_token") if isinstance(data.get("refresh_token"), str) else ""
    if next_refresh == "":
        next_refresh = credential.get("refresh_token") or ""
    merged = dict(credential)
    merged["access_token"] = access_token
    merged["refresh_token"] = next_refresh
    exp_ms = decode_jwt_exp_ms(access_token)
    if exp_ms is not None:
        merged["expires_at"] = str(exp_ms)
    return merged


# ── 模型目录（raccoon-auth.ts 的 fetchModels + parseRaccoonModelCatalog） ────

def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, float) and math.isfinite(value) and value > 0 and value.is_integer():
        return int(value)
    return None


def normalize_remote_model(entry: dict) -> dict | None:
    """归一一个远端模型条目（含展示名）。

    ⚠️ 远端的模型 id 取自 ``entry.name``（这是实测的字段错位，照抄
    ``normalizeRemoteModel``），``description`` 才是展示名主体。
    ⚠️ ``visible`` 缺省视为可见（保守：不因字段缺失而隐藏模型）。
    """
    raw_id = entry.get("name")
    model_id = raw_id.strip() if isinstance(raw_id, str) else ""
    if model_id == "":
        return None
    if entry.get("visible") is False:
        return None
    params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
    description = entry.get("description") if isinstance(entry.get("description"), str) \
        and entry.get("description") != "" else model_id
    effective = entry.get("billing_effective_multiplier")
    effective = float(effective) if isinstance(effective, (int, float)) and not isinstance(effective, bool) else math.nan
    base = entry.get("billing_multiplier")
    base = float(base) if isinstance(base, (int, float)) and not isinstance(base, bool) else math.nan
    status = entry.get("billing_status") if isinstance(entry.get("billing_status"), str) else ""
    tags = [tag for tag in entry.get("tags") or [] if isinstance(tag, str)] \
        if isinstance(entry.get("tags"), list) else []
    meta = {
        "id": model_id,
        "description": description,
        "effectiveMultiplier": effective,
        "baseMultiplier": base,
        "status": status if status in ("discount", "limited_free") else "normal",
        "statusNote": entry.get("billing_status_note") if isinstance(entry.get("billing_status_note"), str) else "",
    }
    context_window = _positive_int(params.get("context_window", entry.get("context_window")))
    max_tokens = _positive_int(params.get("max_tokens"))
    return {
        "id": model_id,
        "name": raccoon_display_name(meta),
        "contextWindow": context_window or 0,
        "maxOutput": max_tokens or 0,
        "vision": raccoon_supports_image(model_id, tags),
        # `extra_body.thinking` 是 **provider 级**方言，与模型无关 → 全模型两态
        "reasoning": True,
        "reasoningEfforts": list(REASONING_EFFORTS),
        "defaultReasoningEffort": DEFAULT_EFFORT,
    }


def parse_model_catalog(payload: Any) -> list[dict]:
    """解析 ``GET /model_catalog``：只取 ``categories[].type === 'chat'`` 的分类。"""
    if not isinstance(payload, dict) or payload.get("code") != 0:
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    categories = data.get("categories") if isinstance(data.get("categories"), list) else []
    chat = next((item for item in categories if isinstance(item, dict) and item.get("type") == "chat"), None)
    if chat is None:
        return []
    models = chat.get("models") if isinstance(chat.get("models"), list) else []
    seen: set[str] = set()
    out: list[dict] = []
    for raw in models:
        if not isinstance(raw, dict):
            continue
        model = normalize_remote_model(raw)
        if model is None or model["id"] in seen:
            continue
        seen.add(model["id"])
        out.append(model)
    return out


def fallback_catalog() -> list[dict]:
    """内置兜底表（``product.ts`` 的 RACCOON_FALLBACK_MODELS）。"""
    return [
        {
            "id": model["id"],
            "name": model["name"],
            "contextWindow": model["contextWindow"],
            "maxOutput": model["maxOutput"],
            "vision": bool(model.get("vision")),
            "reasoning": True,
            "reasoningEfforts": list(REASONING_EFFORTS),
            "defaultReasoningEffort": DEFAULT_EFFORT,
        }
        for model in FALLBACK_MODELS
    ]


async def fetch_models(credential: dict) -> dict:
    """``GET /api/web/llm/v2/model_catalog``；**任何失败都不抛错**，最差回兜底表。"""
    models: list[dict] = []
    try:
        if not isinstance(credential, dict) or not credential.get("access_token"):
            raise UpstreamError("raccoon: 凭据缺少 access_token", CODE["credential"])
        client = await get_client()
        response = await client.get(f"{API_BASE}{MODEL_CATALOG_PATH}",
                                    headers=catalog_headers(credential), timeout=CATALOG_TIMEOUT_S)
        if response.status_code < 400:
            models = parse_model_catalog(response.json())
    except Exception:  # noqa: BLE001
        models = []
    if not models:
        return {"models": fallback_catalog(), "fallback": True}
    return {"models": models, "at": int(time.time() * 1000)}


# ── 推理（raccoon-adapter.ts 的 stream + openai-compat.ts 的序列化） ────────

def thinking_extra_body(effort: Any) -> dict | None:
    """思考档位 → ``extra_body`` 内容（``raccoonThinkingExtraBody``）。

    - 档位为 ``off`` → ``{thinking:{type:'disabled'}}``（真的不产生思考内容）；
    - 其余（含 ``on``/未知档位）→ ``{thinking:{type:'enabled'}}``（宁可多思考，
      不可静默关掉 —— 用户看不到思考内容会以为模型坏了）；
    - **未传档位** → ``None``（不下发该字段，保持服务端默认 = 开）。
    """
    if effort is None or (isinstance(effort, str) and effort == ""):
        return None
    kind = "disabled" if effort == EFFORT_OFF else "enabled"
    return {"thinking": {"type": kind}}


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
        elif isinstance(block, dict) and block.get("type") == "tool-result":
            parts.append(_content_text(block.get("content")))
    return "".join(parts)


def _content_parts(blocks: list) -> list[dict] | None:
    """内部块 / OpenAI parts → 多模态 parts；**无图时返回 None**（保持纯文本形态）。

    ⚠️ 有图就必须返回数组（即便某张图的 URL 缺失也留 ``[image unavailable]``
    占位符），否则图片会被静默吞掉。
    """
    parts: list[dict] = []
    has_image = False
    for raw in blocks:
        if not isinstance(raw, dict):
            continue
        kind = raw.get("type")
        if kind == "text":
            text = str(raw.get("text") or "")
            if text != "":
                parts.append({"type": "text", "text": text})
        elif kind == "image_url":
            has_image = True
            parts.append({"type": "image_url", "image_url": raw.get("image_url") or {}})
        elif kind == "image":
            has_image = True
            attachment = raw.get("attachment") if isinstance(raw.get("attachment"), dict) else {}
            url = attachment.get("url")
            parts.append({"type": "image_url", "image_url": {"url": url}}
                         if isinstance(url, str) and url != "" else {"type": "text", "text": "[image unavailable]"})
        elif kind == "tool-result":
            inner = _content_parts(raw.get("content") if isinstance(raw.get("content"), list) else [])
            if inner is not None:
                has_image = True
                parts.extend(inner)
            else:
                text = _content_text(raw.get("content"))
                if text != "":
                    parts.append({"type": "text", "text": text})
    return parts if (has_image and parts) else None


def serialize_tools(tools: Any) -> list[dict]:
    """工具定义 → 上游形状（``{type:'function', function:{…}}``）。

    ⚠️ ``tools`` 必须真的下发到请求体**顶层**：Qoder/TRAE 都因漏发而让模型在
    正文里臆造 XML 工具调用，harness 认不出 → 任务终止。
    """
    if not isinstance(tools, list):
        return []
    out: list[dict] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = function.get("name")
        if not isinstance(name, str) or name.strip() == "":
            continue
        entry: dict[str, Any] = {"name": name}
        description = function.get("description")
        if isinstance(description, str) and description != "":
            entry["description"] = description
        parameters = function.get("parameters")
        if parameters is not None:
            entry["parameters"] = parameters
        out.append({"type": "function", "function": entry})
    return out


def serialize_messages(messages: Any) -> list[dict]:
    """消息序列化（对齐共享的 ``serializeMessages``）。

    入参是管理器直传的 **OpenAI 形状**（``forward.py`` 把请求体原样交给渠道），
    同时兼容内部块形状：

    - assistant：正文为空且有 ``tool_calls`` 时 ``content`` 必须为 ``null``（OpenAI 规范）；
      思考块折叠回 ``reasoning_content``（原版共享序列化器的字段名）；
    - 工具结果：``role:'tool'`` 消息带 ``tool_call_id``；内部 ``tool-result`` 块
      提升为其后的独立 ``tool`` 消息（该角色 content 只能是字符串）；
    - 图片：内部 ``image`` 块 / OpenAI ``image_url`` part 都转成
      ``{type:'image_url', image_url:{url}}``（服务端唯一接受的形态）。
    """
    if not isinstance(messages, list):
        return []
    wire: list[dict] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role") if isinstance(message.get("role"), str) else "user"
        raw = message.get("content")
        blocks = raw if isinstance(raw, list) else None
        tool_results: list[dict] = []
        regular: list | None = None
        if blocks is not None:
            tool_results = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool-result"]
            regular = [b for b in blocks if not (isinstance(b, dict) and b.get("type") == "tool-result")]
        if role == "assistant":
            text = raw if isinstance(raw, str) else _content_text(regular)
            calls = list(message.get("tool_calls")) if isinstance(message.get("tool_calls"), list) else []
            if not calls and regular is not None:
                for block in regular:
                    if not isinstance(block, dict) or block.get("type") != "tool-call":
                        continue
                    name = block.get("name")
                    if not isinstance(name, str) or name.strip() == "":
                        continue
                    arguments = block.get("arguments")
                    calls.append({"id": str(block.get("id") or ""), "type": "function",
                                  "function": {"name": name,
                                               "arguments": arguments if isinstance(arguments, str) else "{}"}})
            reasoning = message.get("reasoning_content")
            if not isinstance(reasoning, str) or reasoning == "":
                reasoning = message.get("reasoning") if isinstance(message.get("reasoning"), str) else ""
            if reasoning == "" and regular is not None:
                reasoning = "".join(str(b.get("text") or "") for b in regular
                                    if isinstance(b, dict) and b.get("type") == "reasoning")
            entry: dict[str, Any] = {
                "role": "assistant",
                "content": None if (text == "" and calls) else text,
            }
            if reasoning != "":
                entry["reasoning_content"] = reasoning
            if calls:
                entry["tool_calls"] = calls
            wire.append(entry)
            for result in tool_results:
                wire.append({"role": "tool",
                             "tool_call_id": str(result.get("toolCallId") or result.get("tool_call_id") or ""),
                             "content": _content_text(result.get("content")) or "(no output)"})
            continue
        if role == "tool":
            wire.append({
                "role": "tool",
                "tool_call_id": str(message.get("tool_call_id") or ""),
                "content": raw if isinstance(raw, str) else (_content_text(regular) or "(no output)"),
            })
            continue
        if blocks is None:
            wire.append({"role": role, "content": raw if isinstance(raw, str) else _content_text(raw)})
        else:
            parts = _content_parts(regular or [])
            wire.append({"role": role, "content": parts if parts is not None else _content_text(regular or [])})
        for result in tool_results:
            wire.append({"role": "tool",
                         "tool_call_id": str(result.get("toolCallId") or result.get("tool_call_id") or ""),
                         "content": _content_text(result.get("content")) or "(no output)"})
    return wire


def build_payload(body: dict, model_id: str) -> dict:
    """构造上游请求体（字段名与 ``raccoon-adapter.ts`` 的 ``buildBody`` 一致）。"""
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": serialize_messages(body.get("messages")),
        "stream": True,
    }
    max_tokens = _positive_int(body.get("max_tokens"))
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    temperature = body.get("temperature")
    if isinstance(temperature, (int, float)) and not isinstance(temperature, bool):
        payload["temperature"] = temperature
    stop = body.get("stop")
    if isinstance(stop, list) and stop:
        payload["stop"] = stop
    tools = serialize_tools(body.get("tools"))
    if tools:
        payload["tools"] = tools
    # 思考档位（开 / 关）。⚠️ **必须在 `extra_body` 内** —— 实测放顶层会被忽略
    #（连非法值都不报错）。不传档位时不发该字段，保持服务端默认（= 开）。
    thinking = thinking_extra_body(body.get("reasoning_effort"))
    if thinking is not None:
        payload["extra_body"] = thinking
    return payload


def _error_code(status: int) -> str:
    """HTTP 状态码 → 内部失败码（对应 ``httpErrorCode`` + 本项目的 CODE 词表）。"""
    if status in (401, 403):
        return CODE["credential"]
    if status == 429:
        return CODE["quota"]
    if 400 <= status < 500:
        return CODE["client"]
    return CODE["server"]


def _sse_error_message(text: str) -> str:
    """从 SSE 内嵌错误帧 / 非流式 JSON 里取可读原因。"""
    try:
        parsed = json.loads(text)
    except ValueError:
        return text[:200]
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            return error["message"]
        if isinstance(error, str):
            return error
        for key in ("message", "details", "msg"):
            if isinstance(parsed.get(key), str):
                return parsed[key]
    return text[:200]


async def _send_chat(client: httpx.AsyncClient, credential: dict, data: bytes, url: str):
    """发一次 chat 请求；网络失败映射为可重试的 TRANSPORT 失败。"""
    try:
        return await client.send(
            client.build_request("POST", url, headers=chat_headers(credential), content=data),
            stream=True,
        )
    except httpx.HTTPError as error:
        reason = str(error) or error.__class__.__name__
        raise UpstreamError(f"raccoon: transport error: {reason}", CODE["transport"])


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
                "failure": {"message": "raccoon: model returned a completed response with no content",
                            "code": CODE["empty"]}}
    return {"kind": kind}


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """POST 一轮 ``/api/web/llm/v2/chat/completions`` 并以内部 chunk 产出。

    SSE 解析交给 ``read_stream``（``wire="chat"``）：``delta.reasoning_content`` 走
    ``reasoning-delta``（``read_stream`` 同时认 ``reasoning``），``tool_calls`` 按
    ``index`` 合并后走 ``tool-call-delta``，收尾由本函数补 ``usage`` 与 ``finish``。
    401/403 时用 ``refresh_token`` 续期一次后原样重发（raccoon **有** refresh 端点）。
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
            response = await _send_chat(client, credential, data, url)
            if response.status_code in (401, 403):
                await response.aread()
                await response.aclose()
                response = None
                refreshed = await refresh_credential(credential)
                credential = refreshed
                if on_refresh is not None:
                    on_refresh(refreshed)
                response = await _send_chat(client, credential, data, url)
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                raise UpstreamError(f"raccoon: HTTP {response.status_code} {text[:200]}",
                                    _error_code(response.status_code), status=response.status_code)
            head = await read_head(response.aiter_bytes(), 4096, STREAM_TIMEOUT_S)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("raccoon: empty model response body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), channel.push, STREAM_TIMEOUT_S)
            else:
                text = (await _read_remainder(head)).decode("utf-8", "replace")
                try:
                    parsed: Any = json.loads(text)
                except ValueError:
                    raise UpstreamError("raccoon: unexpected non-stream response", CODE["server"])
                # 业务失败可能以 HTTP 200 + 信封返回（code != 0）
                envelope = parse_envelope(parsed, response.status_code)
                if isinstance(parsed, dict) and (parsed.get("error") or (
                        envelope["data"] is None and envelope["code"] != 0)):
                    raise UpstreamError(f"raccoon: {_sse_error_message(text)}", CODE["server"])
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
