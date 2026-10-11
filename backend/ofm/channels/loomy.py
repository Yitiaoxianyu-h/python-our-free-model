"""Loomy（讯飞办公助手 / xfyun ``loomyad``）渠道。

移植自原版 channel-pack 的 ``loomy.ts`` / ``loomy-product.ts`` / ``loomy-sign.ts`` /
``loomy-auth.ts`` / ``loomy-oauth.ts`` / ``loomy-wechat.ts`` / ``loomy-wechat-login.ts`` /
``loomy-adapter.ts``（SSE 语义等价 ``openai-compat.ts`` 的 ``consumeOpenAiSse``）。
本模块只负责「端点 + 鉴权头 + 签名 + 请求体 + 分步登录 + 目录」，逐帧 SSE 解析交给
``..stream.read_stream``（``wire="chat"``），与原版复用 ``openai-compat.ts`` 同一思路。

Loomy 是本项目里**唯一用短信验证码登录**的渠道，故它**不提供一次性** ``run_login``
（管理器一旦发现模块有 ``run_login`` 就会走「后台任务 + 轮询」那条路，短信登录会变成
「没地方输入验证码」的死胡同）。这里只提供分步契约：

1. :func:`start_login` → ``{status:"awaiting-code", needPhone:True, hint:...}``；
2. :func:`submit_login` **带手机号** → 下发短信验证码 → ``{needPhone:False, hint:...}``；
3. :func:`submit_login` **带验证码** → 成功则返回含 ``access_token`` 的凭据 dict。

（另有微信扫码路径，见 :func:`start_wechat_login`；它同样落在 ``start_login`` /
``submit_login`` 的分步契约内，不引入第二条状态机。）

## 三个必须记住的坑（照抄自 ``loomy.ts`` 源码注释）

1. **两套认证头**：``/chat/completions`` 只认 ``Authorization: Bearer``，而 ``/models`` /
   ``/points/*`` 只认小写 ``token``。带错的那个得到的是 HTTP 200 + body
   ``{"code":"100002","desc":"缺少 token"}`` —— 故 chat 请求两个头都发
   （``loomyChatHeaders``），业务请求只发 ``token``（``loomyBusinessHeaders``）。
2. **业务失败恒为 HTTP 200**：成败只能读 body 的 ``code``（``000000`` = 成功，
   ``100002`` = 登录失效且**不得重试**，``100001`` = 参数错误）。只看状态码会把
   「登录已失效」误判成成功，故 :func:`parse_envelope` 是唯一的判据入口。
3. **没有 refresh 端点**：``session`` 是登录时向服务端**声明** ``expire: 1209600``
   （14 天）得来的，响应里不带到期时间戳，凭据的 ``expires_at`` 只能本地推算。
   故 :func:`refresh_credential` **只做有效性探测**（轻量只读 ``/points/records``），
   失效时抛错提示重新登录 —— 诚实标记，不假装续期成功。

## 讯飞账号端点的签名（``loomy-sign.ts`` 逐字节复刻）

    {METHOD}\\n{ESCAPED_PATH}\\n{ESCAPED_QUERY}\\n{Content-MD5}\\n{Content-Type}\\n
    {Date}\\n{Nonce}\\n{SignedHeaders}\\n{CanonicalizedHeaders}

后两段恒为空串（本项目不发任何 ``x-*`` 头），故待签名串**以两个换行结尾**。
认证头前缀是 ``account {ak}:{sig}``（HMAC-SHA1，**不是** Bearer）；``Date`` 用 UTC
字符串、``Nonce`` 用 UUID。**body 必须先序列化成字符串，签名与发送共用同一个字符串**
（二次序列化会改变字节 → 签名失效），本模块由 :func:`_post_account` 强制这一点。

## 不确定之处（如实标注，未编造）

- ``GET /api/v1/models`` 的**调用方式**（``token`` 头、30s 超时）来自 ``index.ts`` 的
  ``fetchRemoteModels``；条目字段名（``id`` / ``name`` / ``type`` / ``context_length`` /
  ``capabilities.input_modalities`` / ``reasoning_efforts`` / ``default_reasoning_effort``）
  来自 ``loomy-adapter.ts`` 的 ``parseLoomyRemoteModels``，但**响应信封层级未在 TS 源码里
  写明**（适配器对 ``{data:[…]}`` 与裸数组都做了兼容），故本模块两种形态都接受。
  远端目录永远只是增强：任何失败都回落到内置兜底表。
- 签到端点 ``POST /points/first-login`` 的请求体在 ``loomy-credits.ts`` 里是 ``{}``，照抄；
  失败一律不阻塞登录（与官方客户端「失败仅 warn」一致）。
- 微信扫码路径在本移植版里是**可选**的（默认关闭，需 ``OFM_LOOMY_WECHAT=1``）：原版依赖
  一个本地 HTTP 服务器承载弹窗页（内联二维码 + 前端轮询 + 绑手机号表单），本移植版没有
  对应前端，故只把二维码 data URL 交回调用方，扫码后仍要短信验证码完成首次绑手机号。
  详见 :func:`start_wechat_login`。
- ``ReasoningEffortId`` 在 Python 侧没有对应类型，思考档位以**字符串**原样透传；且与原版
  一致，``reasoning_effort`` **只在该模型的档位表内存在时**才下发（未声明的档位静默不发 ——
  实测服务端对未知字段静默忽略并回 200，不能靠状态码试错）。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from typing import Any, AsyncIterator, Callable
from urllib.parse import quote

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import finish_reason, read_stream

CHANNEL_ID = "loomy"

# ── 产品配置（loomy-product.ts 的 LOOMY）────────────────────────────────────

API_BASE = "https://loomyad.xunfei.cn/api/v1"      # 业务 / 推理 / 积分 / 新手任务
ACCOUNT_BASE = "https://account.xfinfr.com"        # 讯飞账号（CAccount）

#: 取自官方客户端 ``.env.prod``（``VITE_XFYUN_ACCESS_KEY_ID`` / ``_SECRET`` / ``_APP_ID``）。
#: 只用于**讯飞账号**端点的 HMAC-SHA1 签名（短信验证码登录），与业务/推理端点无关
#: —— 后者用的是用户登录后拿到的 ``session``。
ACCESS_KEY_ID = "2thryby66wxi53sk"
ACCESS_KEY_SECRET = "zsak6eadrbawz683wf5r3m2snrwj868r"
APP_ID = "GM3LOOMY"

DISPLAY_NAME = "Loomy (讯飞)"
DEFAULT_CREDENTIAL_REF = "LOOMY_ACCESS_TOKEN"

# ── 端点路径 ───────────────────────────────────────────────────────────────

SEND_MSG_CODE_PATH = "/login/phone/sendMsgCode"
CHECK_CODE_PATH = "/login/phone/checkCode"
BIND_AUTH_PATH = "/login/thirdAccount/bind/auth"
BIND_SEND_MSG_PATH = "/login/thirdAccount/bind/sendMsg"
BIND_CHECK_CODE_PATH = "/login/thirdAccount/bind/checkCode"
BIND_SKIP_PATH = "/login/thirdAccount/bind/skip"

MODELS_PATH = "/models"
CHAT_PATH = "/chat/completions"
FIRST_LOGIN_PATH = "/points/first-login"
POINTS_RECORDS_PATH = "/points/records?pageNo=1&pageSize=1&recordType=all"

# ── 协议常量（loomy.ts）────────────────────────────────────────────────────

OK_CODE = "000000"           # 业务成功
AUTH_ERROR_CODE = "100002"   # 登录失效；**不得重试**，应标记凭据失效并提示重新登录
BAD_REQUEST_CODE = "100001"  # 参数错误（如未知 task key）

#: 请求超时（秒）；与 Loomy 客户端的 ``LOOMY_REQUEST_TIMEOUT_MS = 60_000`` 一致。
REQUEST_TIMEOUT_S = 60.0
#: 流式推理的读超时（原版首 token / chunk 空闲超时均是 120s）。
STREAM_TIMEOUT_S = 600.0

#: 短信验证码有效期（秒）。
SMS_CODE_TTL_S = 300
#: 登录会话有效期（秒）= 14 天（``account-service.js:391`` 的 ``expire: 14*24*3600``）。
SESSION_TTL_S = 1_209_600

#: 微信扫码长轮询超时（秒）。
WECHAT_POLL_TIMEOUT_S = 40.0
#: 微信开放平台「网站应用」AppID（客户端 ``.env.prod`` 的 ``LOOMY_WECHAT_APP_ID``）。
WECHAT_APP_ID = "wx18d60be432287cf8"
#: ⚠️ **必须是这个官方地址**：微信校验 ``redirect_uri`` 域名白名单，换本地地址会得到
#: 「redirect_uri 参数错误」。它实际返回 404，但我们的链路不需要它可达。
WECHAT_REDIRECT_URI = "https://loomy.xunfei.cn/oauth/wechat/callback"
WECHAT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# ── 模型（loomy-product.ts 的 LOOMY_FALLBACK_MODELS）────────────────────────

#: 实测思考档位：远端对全部 8 个 chat 模型下发同一份档位。
LOOMY_EFFORTS: list[str] = ["none", "low", "medium", "high", "xhigh"]
#: 本插件选用的默认档位（远端声明的 ``low`` **有意不沿用**）。
LOOMY_DEFAULT_EFFORT = "high"

#: 兜底模型目录（8 个 chat 模型；顺序照抄远端返回顺序，不重排）。
FALLBACK_MODELS: list[dict] = [
    {"id": "deepseek-v4-flash-0731", "name": "DeepSeek V4 Flash 0731 · x3.0", "contextWindow": 1_048_576,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "MiniMax-M3", "name": "MiniMax M3 · x4.0", "contextWindow": 1_048_576,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "Kimi-k2.6", "name": "Kimi k2.6 · x6.5", "contextWindow": 262_144,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "qwen-3.8-max", "name": "Qwen 3.8 Max · x12.0", "contextWindow": 1_000_000,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "GLM-5.3-Flash", "name": "GLM 5.3 Flash · x0.8", "contextWindow": 1_048_576,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "qwen3.8-flash", "name": "qwen 3.8 flash · x0.8", "contextWindow": 1_000_000,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "spark-x", "name": "Spark X2.5 · x0.1", "contextWindow": 1_048_576,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
    {"id": "mimo-v2.5", "name": "MiMo V2.5 · x3.3", "contextWindow": 1_048_576,
     "efforts": list(LOOMY_EFFORTS), "defaultEffort": LOOMY_DEFAULT_EFFORT},
]

FALLBACK_INDEX: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS}
CONTEXT_WINDOWS: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS}

#: 已知分歧：远端声明 ``spark-x`` 窗口 1048576，而官方客户端用本地表
#: ``MODEL_CONTEXT_OVERRIDES = { 'spark-x': 262144 }`` 强制降到 262144。
#: 本表**先采信远端**（与 ``loomy-product.ts`` 一致）；此处仅留档，备实测被拒时改用。
KNOWN_CONTEXT_OVERRIDES: dict[str, int] = {"spark-x": 262_144}

# ── 头名 ───────────────────────────────────────────────────────────────────

HEADER_TOKEN = "token"
HEADER_AUTHORIZATION = "Authorization"
HEADER_CONTENT_MD5 = "Content-MD5"
HEADER_DATE = "Date"
HEADER_NONCE = "Nonce"
HEADER_CONTENT_TYPE = "Content-Type"

ACCEPT_SSE = "text/event-stream"
ACCEPT_JSON = "application/json"

#: 账号端点硬编码 UA：客户端在 Windows 上发的也是这个值，照抄不要改。
ACCOUNT_UA = "Loomy|Desktop|Electron|macOS"


# ── 纯函数：签名（loomy-sign.ts）───────────────────────────────────────────


def content_md5(body: str) -> str:
    """计算 ``Content-MD5``（base64）。空 body 返回**空串**（不是空串的 md5）。"""
    if body == "":
        return ""
    return base64.b64encode(hashlib.md5(body.encode("utf-8")).digest()).decode("ascii")


def escape_rfc3986(value: str) -> str:
    """RFC3986 转义：``encodeURIComponent`` + 补转 ``! ' ( ) *``。

    ``quote(safe="-_.~")`` 只保留非保留字符 ``A-Za-z0-9-_.~``，故 ``!'()*`` 同样被转义
    —— 与 ``sign.js:23-42`` 的手工补转结果一致。
    """
    return quote(str(value), safe="-_.~")


def build_escaped_path(raw_path: str) -> str:
    """补前导 ``/``、剥末尾 ``/``（长度 > 1 时），按 ``/`` 切段后**逐段**转义再拼回。"""
    clean = raw_path if raw_path.startswith("/") else f"/{raw_path}"
    if len(clean) > 1 and clean.endswith("/"):
        clean = clean[:-1]
    return "/".join(escape_rfc3986(segment) for segment in clean.split("/"))


def build_escaped_query(query: dict[str, Any] | None) -> str:
    """``key=value`` 用 ``&`` 连接，**不排序**（保持传入顺序），两者都转义。"""
    if not query:
        return ""
    return "&".join(f"{escape_rfc3986(key)}={escape_rfc3986(value)}" for key, value in query.items())


def build_signing_string(*, method: str, path: str, query: dict[str, Any] | None, body: str,
                         content_type: str, date: str, nonce: str) -> str:
    """构建待签名串（9 段，``\\n`` 连接；末两段恒为空 → 以 ``\\n\\n`` 结尾）。

    ⚠️ **不要「顺手」去掉尾随换行** —— 去掉会让签名不匹配。
    """
    return "\n".join([
        method.upper(),
        build_escaped_path(path),
        build_escaped_query(query),
        content_md5(body),
        content_type,
        date,
        nonce,
        "",
        "",
    ])


def _utc_date() -> str:
    """``Date`` 用 UTC 字符串（``Wed, 21 Oct 2015 07:28:00 GMT``，同 ``toUTCString``）。"""
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def account_headers(*, method: str, path: str, body: str = "", query: dict[str, Any] | None = None,
                    content_type: str = "application/json") -> dict[str, str]:
    """生成讯飞账号请求头（``Authorization: account {ak}:{sig}``，HMAC-SHA1）。

    ⚠️ **返回的头必须与签名时的 body 是同一个字符串**：调用方应序列化一次、签名与发送
    共用该字符串（见 :func:`_post_account`），否则键序/空格变了签名立即失效。
    """
    date = _utc_date()
    nonce = str(uuid.uuid4())
    string_to_sign = build_signing_string(method=method, path=path, query=query, body=body,
                                          content_type=content_type, date=date, nonce=nonce)
    signature = base64.b64encode(
        hmac.new(ACCESS_KEY_SECRET.encode("utf-8"), string_to_sign.encode("utf-8"),
                 hashlib.sha1).digest()).decode("ascii")
    headers = {
        HEADER_AUTHORIZATION: f"account {ACCESS_KEY_ID}:{signature}",
        HEADER_DATE: date,
        HEADER_NONCE: nonce,
        HEADER_CONTENT_TYPE: content_type,
    }
    md5 = content_md5(body)
    if md5 != "":
        headers[HEADER_CONTENT_MD5] = md5
    return headers


# ── 鉴权头（loomy.ts 的 loomyBusinessHeaders / loomyChatHeaders）───────────


def business_headers(token: str) -> dict[str, str]:
    """``/models``、``/points/*``、``/onboarding/*``：**只认小写 ``token`` 头**。

    ⚠️ 刻意不加 ``Authorization``：这些端点带 Bearer 会被判「缺少 token」。
    """
    return {"Accept": ACCEPT_JSON, HEADER_TOKEN: token}


def chat_headers(token: str) -> dict[str, str]:
    """chat 端点：``Authorization: Bearer`` 与 ``token`` **两个都发**。

    ⚠️ ``Bearer `` 前缀**必需**：实测无前缀同样回 ``100002 缺少 token``。
    """
    return {
        "Accept": ACCEPT_SSE,
        HEADER_CONTENT_TYPE: "application/json",
        HEADER_AUTHORIZATION: f"Bearer {token}",
        HEADER_TOKEN: token,
    }


# ── 响应信封（loomy.ts 的 parseLoomyEnvelope）──────────────────────────────


def parse_envelope(payload: Any) -> dict:
    """解析业务信封，返回 ``{"ok", "code", "message", "data"}``。

    ⚠️ Loomy 的业务失败**恒返回 HTTP 200**，成败只能读 body 的 ``code``。
    """
    if not isinstance(payload, dict):
        return {"ok": False, "code": "", "message": "响应不是 JSON 对象", "data": None}
    raw_code = payload.get("code")
    code = raw_code if isinstance(raw_code, str) else ("" if raw_code is None else str(raw_code))
    desc = payload.get("desc")
    if isinstance(desc, str) and desc != "":
        message = desc
    else:
        message = payload.get("message") if isinstance(payload.get("message"), str) else ""
    if code != OK_CODE:
        return {"ok": False, "code": code,
                "message": message if message != "" else f"业务错误 {code or '(缺少 code)'}",
                "data": None}
    return {"ok": True, "code": code, "message": message, "data": payload.get("data")}


def is_error_frame(frame: Any) -> bool:
    """判定该帧是否为「业务错误帧」（``code`` 存在且非 ``000000``）。

    判据刻意收窄：正常 SSE 帧里不会出现顶层 ``code``，故不会误伤。
    """
    if not isinstance(frame, dict):
        return False
    code = frame.get("code")
    if code is None or isinstance(code, (dict, list)):
        return False
    return str(code) != OK_CODE


def _business_error(status: int, code: Any, message: str) -> UpstreamError:
    """业务失败（含 HTTP 200 内嵌错误）→ 已分类的 ``UpstreamError``。"""
    code = "" if code is None else str(code)
    text = message if message != "" else f"HTTP {status}"
    if code == AUTH_ERROR_CODE:
        # ⚠️ 收到 100002 **不得重试**：应标记凭据失效并提示重新登录。
        return UpstreamError(f"loomy: 登录已失效，请重新短信登录（{text}）", CODE["credential"], status=status)
    if code == BAD_REQUEST_CODE:
        return UpstreamError(f"loomy: {text}", CODE["client"], status=status)
    return UpstreamError(f"loomy: {text}", CODE["server"] if status >= 500 else CODE["client"], status=status)


# ── 展示名与倍率（loomy.ts 的 splitLoomyRate / loomyDisplayName）───────────

_RATE_BRACKET = re.compile(r"^(.*?)\s*[（(]\s*(x\s*[\d.]+)\s*[)）]\s*$", re.IGNORECASE)
_RATE_NORMALIZED = re.compile(r"^(.*?)\s*·\s*(x\s*[\d.]+)\s*$", re.IGNORECASE)


def split_rate(raw_name: Any) -> tuple[str, str]:
    """从展示名**末尾**抽出倍率，返回 ``(名称, 倍率)``；无倍率时第二项为空串。

    认两种形态（故本函数**幂等**：``split_rate(display_name(x)) == split_rate(x)``）：

    1. 远端原值：末尾括号，全角半角都认、括号前后空格可有可无
       —— 实测三种风格混用：``MiniMax M3 （x4.0）`` / ``Qwen 3.8 Max (x12.0)`` /
       ``GLM 5.3 Flash(x0.8)``；
    2. 已规范化形态 ``{name} · x{n}``（兜底表存的就是这个形态）。
    """
    original = str(raw_name).strip() if isinstance(raw_name, str) else ""
    if original == "":
        return "", ""
    for pattern in (_RATE_BRACKET, _RATE_NORMALIZED):
        found = pattern.match(original)
        if found is None:
            continue
        name = (found.group(1) or "").strip()
        rate = re.sub(r"\s+", "", found.group(2) or "").lower()
        # 主体为空说明整个 name 就是个括号（畸形数据）：原样保留，不产出空名字。
        return (name, rate) if name != "" else (original, "")
    return original, ""


def display_name(raw_name: Any) -> str:
    """最终展示名 ``MiniMax M3 · x4.0``；无倍率时不追加分隔符。"""
    name, rate = split_rate(raw_name)
    return f"{name} · {rate}" if rate != "" else name


# ── 账号端点（loomy-oauth.ts）──────────────────────────────────────────────


def build_account_body(param: dict) -> dict:
    """构建账号端点请求体信封 ``{base, param}``（``traceid`` 每次调用重新生成）。"""
    return {
        "base": {
            "appid": APP_ID,
            "modelid": "Web",
            "version": "1.0.0",
            "devid": "web",
            # ⚠️ 硬编码 macOS：客户端在 Windows 上发的也是这个值，照抄不要改。
            "ua": ACCOUNT_UA,
            "traceid": uuid.uuid4().hex,
        },
        "param": param,
    }


async def _post_account(path: str, param: dict, *, timeout_s: float = REQUEST_TIMEOUT_S) -> Any:
    """POST 一次账号端点并拆信封。

    ⚠️ body 只序列化**一次**、签名与发送共用该字符串 —— 这是签名能通过的前提。
    """
    serialized = json.dumps(build_account_body(param), separators=(",", ":"), ensure_ascii=False)
    headers = account_headers(method="POST", path=path, body=serialized)
    client = await get_client()
    try:
        response = await client.post(f"{ACCOUNT_BASE}{path}", headers=headers,
                                     content=serialized.encode("utf-8"), timeout=timeout_s)
    except httpx.HTTPError as error:
        raise UpstreamError(f"loomy: 讯飞账号请求失败（{path}）：{error}", CODE["transport"]) from error
    try:
        parsed = response.json()
    except ValueError:
        raise UpstreamError(f"loomy: 讯飞账号响应不是 JSON（{path}，HTTP {response.status_code}）",
                            CODE["server"], status=response.status_code)
    envelope = parse_envelope(parsed)
    if not envelope["ok"]:
        # 账号端点的鉴权错误码与业务端点不同（实测 ``020002`` 也是登录态问题），但对本模块
        # 而言都是「这次调用失败」，直接透传 desc 即可 —— 上层据文案判断
        # 「验证码错误」还是「手机号格式不正确」。
        raise UpstreamError(f"loomy: {envelope['message'] or f'讯飞账号请求失败（{path}）'}",
                            CODE["credential"] if response.status_code in (401, 403)
                            or envelope["code"] == AUTH_ERROR_CODE else CODE["client"],
                            status=response.status_code, businessCode=envelope["code"])
    return envelope["data"]


async def send_sms_code(phone: str) -> str:
    """下发短信验证码，返回 ``msgid``（提交验证码时必须原样带回）。"""
    data = await _post_account(SEND_MSG_CODE_PATH, {"ccode": "86", "phone": phone, "expire": SMS_CODE_TTL_S})
    msgid = data.get("msgid") if isinstance(data, dict) else None
    if not isinstance(msgid, str) or msgid == "":
        # 不返回空串：上层会拿它去登录，服务端必然报「msgid 无效」，
        # 用户看到的将是一个与真实原因无关的错误。
        raise UpstreamError("loomy: 短信验证码响应缺少 msgid", CODE["server"])
    return msgid


async def login_by_sms_code(phone: str, code: str, msgid: str) -> dict:
    """用短信验证码登录，返回 ``{"session", "userid"}``。"""
    data = await _post_account(CHECK_CODE_PATH, {"ccode": "86", "phone": phone, "mcode": code,
                                                "msgid": msgid, "expire": SESSION_TTL_S})
    record = data if isinstance(data, dict) else {}
    session = record.get("session") if isinstance(record.get("session"), str) else ""
    userid = record.get("userid") if isinstance(record.get("userid"), str) else ""
    if session == "":
        raise UpstreamError("loomy: 登录响应缺少 session", CODE["server"])
    if userid == "":
        raise UpstreamError("loomy: 登录响应缺少 userid", CODE["server"])
    return {"session": session, "userid": userid}


async def bind_third_account(code: str) -> dict:
    """微信扫码第 1 步：用微信 ``code`` 换 ``rcode``，并得知是否已绑手机号。

    ⚠️ ``bind`` 缺失时**归为 0**（走绑定流程）：保守方向 —— 若实际已绑，用户最多多填
    一次手机号；若实际未绑却跳过，会拿到一个没有手机号的账号。
    """
    data = await _post_account(BIND_AUTH_PATH, {"tcode": {"code": code}, "type": "wx"})
    record = data if isinstance(data, dict) else {}
    rcode = record.get("rcode") if isinstance(record.get("rcode"), str) else ""
    if rcode == "":
        raise UpstreamError("loomy: 微信授权响应缺少 rcode", CODE["server"])
    return {
        "bind": 1 if record.get("bind") == 1 else 0,
        "rcode": rcode,
        "isnew": record.get("isnew") if isinstance(record.get("isnew"), int) else None,
        "nickname": record.get("nickname") if isinstance(record.get("nickname"), str) else "",
        "headpic": record.get("headpic") if isinstance(record.get("headpic"), str) else "",
    }


async def bind_send_msg(rcode: str, phone: str) -> str:
    """微信扫码第 2 步：向待绑定手机号下发验证码，返回 ``msgid``。"""
    data = await _post_account(BIND_SEND_MSG_PATH, {"rcode": rcode, "phone": phone,
                                                   "ccode": "86", "expire": SMS_CODE_TTL_S})
    msgid = data.get("msgid") if isinstance(data, dict) else None
    if not isinstance(msgid, str) or msgid == "":
        raise UpstreamError("loomy: 绑定手机号响应缺少 msgid", CODE["server"])
    return msgid


async def bind_check_code(rcode: str, code: str, msgid: str) -> dict:
    """微信扫码第 3 步：验证短信验证码，通过即完成绑定 + 登录。"""
    data = await _post_account(BIND_CHECK_CODE_PATH, {"rcode": rcode, "mcode": code,
                                                      "msgid": msgid, "expire": SESSION_TTL_S})
    record = data if isinstance(data, dict) else {}
    session = record.get("session") if isinstance(record.get("session"), str) else ""
    userid = record.get("userid") if isinstance(record.get("userid"), str) else ""
    phone = record.get("phone") if isinstance(record.get("phone"), str) else ""
    if session == "":
        raise UpstreamError("loomy: 绑定登录响应缺少 session", CODE["server"])
    if userid == "":
        raise UpstreamError("loomy: 绑定登录响应缺少 userid", CODE["server"])
    return {"session": session, "userid": userid, "phone": phone}


async def bind_skip(rcode: str) -> dict:
    """微信扫码第 4 步（``bind == 1`` 时走）：跳过绑定，直接换 ``session``。"""
    data = await _post_account(BIND_SKIP_PATH, {"rcode": rcode, "expire": SESSION_TTL_S})
    record = data if isinstance(data, dict) else {}
    session = record.get("session") if isinstance(record.get("session"), str) else ""
    userid = record.get("userid") if isinstance(record.get("userid"), str) else ""
    if session == "":
        raise UpstreamError("loomy: 微信登录响应缺少 session", CODE["server"])
    if userid == "":
        raise UpstreamError("loomy: 微信登录响应缺少 userid", CODE["server"])
    return {"session": session, "userid": userid}


# ── 业务端点调用（积分 / 额度 / 有效性探测）────────────────────────────────


async def claim_daily_quota(credential: dict) -> bool:
    """尽力初始化每日赠送额度（``POST /points/first-login``）；失败**不影响登录**。

    ⚠️ 语义是「触发每日额度重置」，**不是**「+5000 积分」（``dailyBalance =
    dailyQuota - dailyConsumed``，消耗后不回补）。
    """
    token = str((credential or {}).get("access_token") or "")
    if token == "":
        return False
    try:
        client = await get_client()
        response = await client.post(f"{API_BASE}{FIRST_LOGIN_PATH}", headers=business_headers(token),
                                     content=b"{}", timeout=REQUEST_TIMEOUT_S)
        payload = response.json()
    except Exception:  # noqa: BLE001  —— 只是额度初始化，任何失败都吞掉
        return False
    return bool(parse_envelope(payload)["ok"])


async def probe_credential(credential: dict) -> bool:
    """用一次轻量只读请求确认凭据是否仍然有效（``GET /points/records?pageSize=1``）。

    ⚠️ Loomy **没有 refresh 端点**，故这不是续期，只是「确认这份凭据还活着」。
    选 ``/points/records`` 的理由：最便宜的只读端点（不消耗积分、无副作用）。

    :raises UpstreamError: 收到 ``100002``（登录已失效，且**不得重试**）。
    """
    token = str((credential or {}).get("access_token") or "")
    if token == "":
        raise UpstreamError("loomy: 凭据缺少 access_token，请重新登录", CODE["credential"])
    client = await get_client()
    response = await client.get(f"{API_BASE}{POINTS_RECORDS_PATH}", headers=business_headers(token),
                                timeout=REQUEST_TIMEOUT_S)
    try:
        payload = response.json()
    except ValueError:
        raise UpstreamError(f"loomy: 积分查询响应不是 JSON（HTTP {response.status_code}）", CODE["server"],
                            status=response.status_code)
    envelope = parse_envelope(payload)
    if not envelope["ok"]:
        raise UpstreamError(f"loomy: 登录已失效，请重新短信登录（{envelope['message']}）", CODE["credential"],
                            status=response.status_code, businessCode=envelope["code"])
    return True


async def refresh_credential(credential: dict) -> dict:
    """**探测**凭据有效性（不是续期）；仍有效则原样返回，已失效则抛凭据错误。

    与其余渠道的 ``refresh_credential`` 语义差异是**有意的**：Loomy 没有 refresh 端点，
    这里唯一能诚实做的事就是「确认还活着」，故绝不返回一份假的「新凭据」。
    """
    await probe_credential(credential)
    return credential


# ── 凭据（loomy-auth.ts 的 buildCredential / isLoomyExpired）───────────────


def build_credential(session: str, userid: str, phone: str = "", nickname: str = "",
                     extra: dict | None = None) -> dict:
    """构造凭据对象。

    ⚠️ ``access_token`` 字段名**必须**是这个（管理器与账号池都按它取身份标识），
    值是讯飞下发的 32 位小写 hex ``session``。
    ⚠️ ``expires_at`` 由**本地**按 14 天推算 —— 服务端响应里不带到期时间戳，
    它只接受登录请求里的 ``expire`` 参数。
    """
    credential: dict[str, Any] = {
        "access_token": session,
        "userid": userid,
        "phone": phone,
        "expires_at": str(int(time.time() * 1000) + SESSION_TTL_S * 1000),
    }
    if nickname != "":
        credential["nickname"] = nickname
    if extra:
        for key, value in extra.items():
            if value not in (None, ""):
                credential[key] = value
    return credential


def credential_expires_at_ms(credential: Any) -> int | None:
    """解析 ``expires_at``（毫秒时间戳字符串）；缺失或非法返回 ``None``。"""
    raw = credential.get("expires_at") if isinstance(credential, dict) else None
    text = str(raw).strip() if raw is not None else ""
    if text == "":
        return None
    try:
        value = int(float(text))
    except ValueError:
        return None
    return value if value > 0 else None


def is_expired(credential: Any) -> bool:
    """凭据是否已过期。

    无 ``expires_at`` 时视为**不过期**：宁可用一个可能过期的凭据去试（服务端会回
    ``100002``，我们能识别），也不要凭猜测阻止用户使用。
    """
    expires_at = credential_expires_at_ms(credential)
    return expires_at is not None and expires_at <= int(time.time() * 1000)


def is_refreshable(credential: Any) -> bool:
    """恒 ``False``：Loomy 没有任何 refresh 端点（**诚实标记**，不是遗漏）。"""
    del credential
    return False


# ── 分步登录（短信验证码）──────────────────────────────────────────────────
#
# 管理器同一时刻只跑一条登录流程（``ChannelManager._logins`` 每个渠道一个任务，且分步登录
# 是直接 await），故这里的模块级状态等价于原版「本地服务器里的 FlowState」。

_LOGIN_STATE: dict[str, Any] = {}

_START_HINT = "请输入手机号（中国大陆 11 位，可带 +86），提交后会下发短信验证码"
_CODE_HINT = "请输入短信验证码；如未收到可再次提交手机号重发"

#: 短信验证码：4~8 位纯数字（讯飞短信码实测 6 位，放宽到 4~8 以免上游改长度时误判）。
_CODE_PATTERN = re.compile(r"^\d{4,8}$")


def _digits(value: Any) -> str:
    """从用户输入里抽出 11 位手机号（容忍 ``+86`` / 空格 / 连字符）。"""
    plain = re.sub(r"[^0-9]", "", str(value or ""))
    if plain.startswith("86") and len(plain) == 13:
        plain = plain[2:]
    return plain


def _reset_login_state() -> None:
    _LOGIN_STATE.clear()


def login_state() -> dict:
    """当前登录状态（仅供排查，不参与协议；**不含**任何密钥材料）。"""
    return {key: value for key, value in _LOGIN_STATE.items() if key != "wechat_uuid"}


async def start_login() -> dict:
    """**第 1 步**：发起登录（短信验证码路径）。

    无参数。返回 ``{"status": "awaiting-code", "hint": ..., "needPhone": True}``，
    前端据此渲染「手机号」输入框。
    """
    _reset_login_state()
    _LOGIN_STATE["phase"] = "phone"
    return {"status": "awaiting-code", "hint": _START_HINT, "needPhone": True}


async def submit_login(payload: dict) -> dict:
    """**第 2 / 3 步**：提交手机号（下发验证码）或验证码（完成登录）。

    ``payload`` 可能含：

    - ``phone``：手机号。**不带验证码**时即「下发验证码」；
    - ``code``：短信验证码。带它时即「校验并登录」；
    - 两者都给时以 ``code`` 为主（本项目前端一直把 ``{code, phone}`` 一起提交）。

    返回 ``{"status": "awaiting-code", "hint": ...}``，或成功时返回凭据 dict
    （含 ``access_token``，由管理器落盘并登记账号）。

    ⚠️ 单步失败（验证码错、手机号格式错、频控）**不终止**整个流程：异常由管理器兜住并
    以 ``status: error`` 回给前端，用户可再次提交（与官方客户端一致）。
    """
    state = payload if isinstance(payload, dict) else {}
    phone = _digits(state.get("phone"))
    code = str(state.get("code") or "").strip()
    phase = _LOGIN_STATE.get("phase")

    # ── 冷启动兜底：进程重启后状态丢了，但前端仍在提交 ──────────────────────
    if phase is None:
        if phone == "":
            _LOGIN_STATE["phase"] = "phone"
            return {"status": "awaiting-code", "hint": _START_HINT, "needPhone": True}
        if code != "":
            if _CODE_PATTERN.match(code):
                _LOGIN_STATE["phase"] = "code"
            else:
                # 一个既不是手机号、也不是验证码的串：当作手机号试一次下发。
                _LOGIN_STATE["phase"] = "phone"

    phase = _LOGIN_STATE.get("phase")

    # ── 3. 提交验证码：完成登录（或完成微信绑手机号）────────────────────────
    if code != "":
        if phase in ("bind", "bind-code") or _LOGIN_STATE.get("rcode"):
            return await _finish_wechat_bind(phone, code)
        msgid = _LOGIN_STATE.get("msgid")
        if not isinstance(msgid, str) or msgid == "":
            return {"status": "awaiting-code", "needPhone": True,
                    "hint": "登录会话已失效，请重新提交手机号以获取验证码"}
        target = str(_LOGIN_STATE.get("phone") or phone)
        if target == "":
            return {"status": "awaiting-code", "needPhone": True,
                    "hint": "缺少手机号，请重新提交手机号以获取验证码"}
        login = await login_by_sms_code(target, code, msgid)
        _reset_login_state()
        credential = build_credential(login["session"], login["userid"], target)
        await claim_daily_quota(credential)
        return credential

    # ── 2. 只提交手机号：下发验证码 ─────────────────────────────────────────
    if len(phone) != 11 or not phone.startswith("1"):
        # 讯飞侧也会回错，但本地先拦一次能省一次往返、也给出更准确的提示。
        return {"status": "awaiting-code", "needPhone": True,
                "hint": f"手机号格式不正确（{state.get('phone')!r}），请输入中国大陆 11 位手机号"}

    if phase == "bind" or _LOGIN_STATE.get("rcode"):
        rcode = str(_LOGIN_STATE.get("rcode") or "")
        msgid = await bind_send_msg(rcode, phone)
        _LOGIN_STATE.update({"phase": "bind-code", "phone": phone, "bind_msgid": msgid})
        return {"status": "awaiting-code", "needPhone": False,
                "hint": f"验证码已发送至 {phone}，请输入短信验证码完成手机号绑定"}

    msgid = await send_sms_code(phone)
    _LOGIN_STATE.update({"phase": "code", "phone": phone, "msgid": msgid})
    return {"status": "awaiting-code", "needPhone": False,
            "hint": f"验证码已发送至 {phone}，请{_CODE_HINT.lstrip('请')}"}


async def _finish_wechat_bind(phone: str, code: str) -> dict:
    """微信扫码路径的收尾：``bindCheckCode`` → 凭据。"""
    rcode = str(_LOGIN_STATE.get("rcode") or "")
    msgid = str(_LOGIN_STATE.get("bind_msgid") or "")
    if msgid == "":
        return {"status": "awaiting-code", "needPhone": True,
                "hint": "请先提交手机号以获取绑定用验证码"}
    login = await bind_check_code(rcode, code, msgid)
    target = login.get("phone") or phone or str(_LOGIN_STATE.get("phone") or "")
    nickname = str(_LOGIN_STATE.get("nickname") or "")
    _reset_login_state()
    credential = build_credential(login["session"], login["userid"], target, nickname,
                                 extra={"login_via": "wechat"})
    await claim_daily_quota(credential)
    return credential


# ── 微信扫码（可选路径；loomy-wechat.ts / loomy-wechat-login.ts）────────────


def _wechat_enabled() -> bool:
    return (os.environ.get("OFM_LOOMY_WECHAT", "0") or "0").strip().lower() in ("1", "true", "yes", "on")


def build_wechat_auth_url(state: str) -> str:
    """拼微信授权页 URL（``redirect_uri`` 必须是官方地址，微信校验域名白名单）。"""
    return ("https://open.weixin.qq.com/connect/qrconnect"
            f"?appid={quote(WECHAT_APP_ID, safe='')}"
            f"&redirect_uri={quote(WECHAT_REDIRECT_URI, safe='')}"
            "&response_type=code&scope=snsapi_login"
            f"&state={quote(str(state), safe='')}#wechat_redirect")


def build_wechat_qr_image_url(uuid_value: str) -> str:
    """拼二维码图片地址（实测返回 **JPEG**，约 47KB，可转 data URL 渲染）。"""
    return f"https://open.weixin.qq.com/connect/qrcode/{quote(uuid_value, safe='')}"


#: 二维码 uuid 的字符集（实测形如 ``001ZDsw64Vu7ll2E`` / ``4Y0N_jyVQg==``）。
_UUID_PATTERN = re.compile(r"^[A-Za-z0-9_\-=+/]{6,64}$")


def extract_wechat_uuid(html: Any) -> str:
    """从授权页 HTML 提取二维码 uuid（页面**直接内嵌**，无需执行 JS）。

    两条路径互为兜底：``<img class="js_qrcode_img" src="/connect/qrcode/<uuid>">``（主）
    与 ``l/qrconnect?uuid=<uuid>``（兜底）。提取不到返回空串。
    """
    if not isinstance(html, str) or html == "":
        return ""
    for pattern in (r"/connect/qrcode/([A-Za-z0-9_\-=+/]+)", r"l/qrconnect\?uuid=([A-Za-z0-9_\-=+/]+)"):
        found = re.search(pattern, html)
        if found is not None and _UUID_PATTERN.match(found.group(1)):
            return found.group(1)
    return ""


async def fetch_wechat_uuid(state: str) -> str:
    """拉取授权页并提取二维码 uuid（失败抛错）。"""
    client = await get_client()
    try:
        response = await client.get(build_wechat_auth_url(state),
                                    headers={"User-Agent": WECHAT_UA, "Referer": "https://open.weixin.qq.com/"},
                                    timeout=30.0)
    except httpx.HTTPError as error:
        raise UpstreamError(f"loomy: 微信授权页拉取失败：{error}", CODE["transport"]) from error
    if response.status_code >= 400:
        raise UpstreamError(f"loomy: 微信授权页返回 HTTP {response.status_code}", CODE["server"])
    uuid_value = extract_wechat_uuid(response.text)
    if uuid_value == "":
        raise UpstreamError("loomy: 微信授权页未包含二维码 uuid（页面结构可能已变化）", CODE["server"])
    return uuid_value


async def fetch_wechat_qr_data_url(uuid_value: str) -> str:
    """下载二维码图片并转成 data URL（PNG / JPEG / GIF 三种魔数都认）。"""
    client = await get_client()
    try:
        response = await client.get(build_wechat_qr_image_url(uuid_value),
                                    headers={"User-Agent": WECHAT_UA, "Referer": "https://open.weixin.qq.com/"},
                                    timeout=30.0)
    except httpx.HTTPError as error:
        raise UpstreamError(f"loomy: 微信二维码下载失败：{error}", CODE["transport"]) from error
    if response.status_code >= 400:
        raise UpstreamError(f"loomy: 微信二维码返回 HTTP {response.status_code}", CODE["server"])
    data = response.content
    mime = _detect_image_mime(data)
    if mime == "" or len(data) < 200:
        raise UpstreamError("loomy: 微信二维码响应不是图片（可能是错误页）", CODE["server"])
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def _detect_image_mime(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:4] == b"\x89PNG":
        return "image/png"
    if data[:3] == b"GIF":
        return "image/gif"
    return ""


#: 长轮询状态（语义以微信授权页内嵌 JS 的 ``switch(window.wx_errcode)`` 为准）。
WECHAT_WAITING = "waiting"      # 408 待扫码（常态）
WECHAT_SCANNED = "scanned"      # 404 已扫码待确认（**继续轮询**）
WECHAT_CONFIRMED = "confirmed"  # 405 **已确认**，``wx_code`` 就在这一帧
WECHAT_CANCELLED = "cancelled"  # 403 用户取消
WECHAT_EXPIRED = "expired"      # 402 二维码失效


async def poll_wechat_once(uuid_value: str, last_errcode: str) -> dict:
    """执行一次微信长轮询；网络异常归 ``waiting`` 而**不抛错**（偶发失败不该终止流程）。"""
    query = f"uuid={quote(uuid_value, safe='')}"
    if last_errcode != "":
        query += f"&last={quote(last_errcode, safe='')}"
    query += f"&_={int(time.time() * 1000)}"
    client = await get_client()
    try:
        response = await client.get(f"https://long.open.weixin.qq.com/connect/l/qrconnect?{query}",
                                    headers={"User-Agent": WECHAT_UA,
                                             "Referer": build_wechat_auth_url("")},
                                    timeout=WECHAT_POLL_TIMEOUT_S)
        body = response.text
    except httpx.HTTPError as error:
        return {"status": WECHAT_WAITING, "code": "", "errcode": str(error)}
    found = re.search(r"wx_errcode\s*=\s*(\d+)", body)
    errcode = found.group(1) if found is not None else ""
    code_found = re.search(r"wx_code\s*=\s*'([^']*)'", body)
    code = code_found.group(1) if code_found is not None else ""
    if errcode == "405":
        # ⚠️ 405 = **已确认**；没带 code 时保守判「已扫码」，**绝不**拿空 code 去换 session。
        if code != "":
            return {"status": WECHAT_CONFIRMED, "code": code, "errcode": errcode}
        return {"status": WECHAT_SCANNED, "code": "", "errcode": errcode}
    if errcode == "404":
        return {"status": WECHAT_SCANNED, "code": "", "errcode": errcode}
    if errcode == "403":
        return {"status": WECHAT_CANCELLED, "code": "", "errcode": errcode}
    if errcode == "402":
        return {"status": WECHAT_EXPIRED, "code": "", "errcode": errcode}
    # 408 与未知值一律归 waiting（保守：绝不误判成功）。
    return {"status": WECHAT_WAITING, "code": "", "errcode": errcode}


async def start_wechat_login() -> dict:
    """**可选路径**：发起微信扫码登录（需 ``OFM_LOOMY_WECHAT=1``）。

    ⚠️ 为什么默认关闭：原版的扫码流程依赖**本地 HTTP 服务器**承载弹窗页（内联二维码 +
    前端轮询 + 绑手机号表单），本移植版没有对应前端。这里退化为标准分步契约：
    返回二维码 ``qr``（data URL，前端 ``<img src>`` 可直接渲染），调用方拿到微信 ``code``
    后 ``submit_login({"code": code})`` 换 ``rcode``；若讯飞侧尚未绑手机号，则仍要
    ``submit_login({"phone": ...})`` + ``submit_login({"code": 短信码})`` 完成绑定。
    因为多一步「调用方自行提交微信 code」，故**不设为默认登录方式**。
    """
    if not _wechat_enabled():
        raise UpstreamError("loomy: 微信扫码登录未启用（设置 OFM_LOOMY_WECHAT=1 可启用）；"
                            "默认请使用短信验证码登录", CODE["client"])
    _reset_login_state()
    uuid_value = await fetch_wechat_uuid(secrets.token_hex(16))
    _LOGIN_STATE.update({"phase": "wechat", "wechat_uuid": uuid_value, "last_errcode": ""})
    qr = await fetch_wechat_qr_data_url(uuid_value)
    return {"status": "awaiting-code", "needPhone": False, "qr": qr,
            "hint": "请用微信扫码并在手机上确认，然后提交微信返回的 code"}


async def submit_wechat_code(code: str) -> dict:
    """微信路径的中间步：用微信 ``code`` 换 ``rcode``（已绑手机号则直接拿凭据）。"""
    auth = await bind_third_account(code)
    _LOGIN_STATE.update({"rcode": auth["rcode"], "bind": auth["bind"],
                         "nickname": auth.get("nickname") or ""})
    if auth["bind"] == 1:
        # 已绑手机号：直接 skip 换 session，整个流程结束。
        login = await bind_skip(auth["rcode"])
        nickname = str(auth.get("nickname") or "")
        _reset_login_state()
        credential = build_credential(login["session"], login["userid"], "", nickname,
                                     extra={"login_via": "wechat"})
        await claim_daily_quota(credential)
        return credential
    _LOGIN_STATE["phase"] = "bind"
    return {"status": "awaiting-code", "needPhone": True,
            "hint": "该微信号尚未绑定讯飞手机号，请输入手机号以获取绑定验证码"}


# ── 模型目录（index.ts 的 fetchRemoteModels + loomy-adapter.ts 的解析）─────

_REMOTE_LIST_KEYS = ("models", "data", "list", "items")


def parse_remote_models(payload: Any) -> list[dict]:
    """解析远端 ``GET /models`` 响应，只保留 ``type == "chat"`` 的条目。

    ⚠️ 过滤判据是 ``type``，**不能**看 ``input_modalities`` —— 实测 5 个 chat 模型的
    输入模态含 ``image``（能看图），那是输入多模态，与「是不是生图模型」无关。
    ⚠️ 展示名经 :func:`display_name` 规范化（远端原值是三种括号风格混用）。
    ⚠️ 档位缺失时**不写** ``reasoningEfforts`` 键（而不是写空数组）：下游据此区分
    「该模型不提供档位」与「提供了但为空」。
    """
    rows: list = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in _REMOTE_LIST_KEYS:
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
    models: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        model_id = str(row.get("id") or "").strip()
        if model_id == "" or row.get("type") != "chat" or model_id in seen:
            continue
        seen.add(model_id)
        raw_name = row.get("name") if isinstance(row.get("name"), str) and row["name"] else model_id
        try:
            context_window = int(float(row.get("context_length")))
        except (TypeError, ValueError):
            context_window = 0
        capabilities = row.get("capabilities") if isinstance(row.get("capabilities"), dict) else {}
        modalities = capabilities.get("input_modalities")
        vision = isinstance(modalities, list) and any(
            isinstance(item, str) and item.lower() == "image" for item in modalities)
        efforts = [item for item in (row.get("reasoning_efforts") or [])
                   if isinstance(item, str) and item != ""]
        entry: dict[str, Any] = {
            "id": model_id,
            "name": display_name(raw_name),
            "contextWindow": context_window if context_window > 0 else 0,
            "vision": bool(vision),
            "reasoning": capabilities.get("reasoning") is True,
        }
        if efforts:
            entry["reasoningEfforts"] = efforts
        default_effort = row.get("default_reasoning_effort")
        if isinstance(default_effort, str) and default_effort != "":
            entry["defaultReasoningEffort"] = default_effort
        models.append(entry)
    return models


def fallback_catalog() -> dict:
    """内置兜底表（``loomy-product.ts`` 的 ``LOOMY_FALLBACK_MODELS``，8 个 chat 模型）。"""
    return {"models": [dict(model) for model in FALLBACK_MODELS], "source": "fallback"}


async def fetch_models(credential: dict) -> dict:
    """``GET {API_BASE}/models``（**token 头**）；任何失败都**不抛错**，最差返回兜底表。

    ⚠️ 必须用 ``token`` 头而不是 Bearer：带错会得到 ``100002 缺少 token``，
    表现为「模型列表永远停在兜底表」。
    """
    try:
        token = str((credential or {}).get("access_token") or "")
        if token == "":
            raise UpstreamError("loomy: 凭据缺少 access_token", CODE["credential"])
        client = await get_client()
        response = await client.get(f"{API_BASE}{MODELS_PATH}", headers=business_headers(token),
                                    timeout=30.0)
        if response.status_code < 400:
            payload = response.json()
            # 远端可能包一层业务信封（``{code, desc, data}``）：成功码才取 ``data``。
            envelope = parse_envelope(payload)
            models = parse_remote_models(envelope["data"] if envelope["ok"] else payload)
            if models:
                return {"models": models, "source": "remote"}
    except Exception:  # noqa: BLE001  —— 目录是增强，失败必须静默回落
        pass
    return fallback_catalog()


# ── 推理（loomy-adapter.ts 的 stream + openai-compat.ts 的序列化语义）──────


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, float) and value.is_integer() and value > 0:
        return int(value)
    return None


def _catalog_model(catalog: Any, model_id: str) -> dict | None:
    if not isinstance(catalog, dict):
        return None
    for model in catalog.get("models") or []:
        if isinstance(model, dict) and model.get("id") == model_id:
            return model
    return None


def efforts_for(model_id: str, catalog: Any) -> list[str]:
    """可枚举思考档位：远端 ``reasoning_efforts`` → 兜底表 ``efforts`` → 空列表。"""
    remote = _catalog_model(catalog, model_id) or {}
    remote_efforts = remote.get("reasoningEfforts")
    if isinstance(remote_efforts, list) and remote_efforts:
        return [effort for effort in remote_efforts if isinstance(effort, str) and effort != ""]
    declared = (FALLBACK_INDEX.get(model_id) or {}).get("efforts")
    if isinstance(declared, list) and declared:
        return [effort for effort in declared if isinstance(effort, str) and effort != ""]
    return []


def default_effort_for(model_id: str, catalog: Any) -> str | None:
    """本插件选用的默认档位（``high``），**必须**落在该模型的档位表内，否则返回 ``None``。

    ⚠️ 远端声明的 ``default_reasoning_effort`` 是 ``low``，这里**有意不沿用**（用户要求）；
    但沿用同一套「不在档位表内就不声明」的校验 —— 给一个远端不认的档位比不给更糟。
    """
    efforts = efforts_for(model_id, catalog)
    return LOOMY_DEFAULT_EFFORT if LOOMY_DEFAULT_EFFORT in efforts else None


def _content_to_text(content: Any) -> str:
    """把消息载荷展平为纯文本（多模态 parts 只取 text，同 ``contentToText``）。"""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict):
            text = block.get("text") or block.get("input_text") or block.get("output_text")
            if isinstance(text, str) and text != "":
                parts.append(text)
    return "".join(parts)


def serialize_messages(messages: Any) -> list[dict]:
    """把 OpenAI 形状消息选净后转成 wire 形状。

    只做**协议必需**的清理（与 ``openai-compat.ts`` 的通用规则一致）：

    - 多模态 parts 展平为纯文本（兜底表不声明图片能力，见 ``fallbackToRemote``）；
    - 正文为空且带 ``tool_calls`` 时 ``content`` 必须为 ``null``（OpenAI 规范）；
    - 保留 ``reasoning_content``（原版的历史回填字段）；
    - ``developer`` 角色归一为 ``system``。

    ⚠️ **孤儿工具调用 / 工具结果的配对修复不在这里**：那是 ``ofm`` 入口侧
    ``messages.repair_tool_pairing`` 的职责，本模块不重复实现，避免两套语义漂移。
    """
    if not isinstance(messages, list):
        return []
    wire: list[dict] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role not in ("system", "developer", "user", "assistant", "tool"):
            continue
        entry: dict[str, Any] = dict(message)
        if role == "developer":
            entry["role"] = "system"
        content = message.get("content")
        if role == "assistant":
            text = content if isinstance(content, str) else _content_to_text(content)
            calls = message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else []
            entry["content"] = None if (text == "" and calls) else text
            reasoning = message.get("reasoning_content")
            if isinstance(reasoning, str) and reasoning != "":
                entry["reasoning_content"] = reasoning
            else:
                entry.pop("reasoning_content", None)
        elif isinstance(content, list):
            entry["content"] = _content_to_text(content)
        wire.append(entry)
    return wire


def max_tokens_for(model_id: str, body: dict, catalog: Any) -> int | None:
    """输出额度：调用方显式值 → 远端 ``maxOutput`` → 兜底表 ``maxOutput``。"""
    explicit = _positive_int(body.get("max_tokens"))
    if explicit is not None:
        return explicit
    remote = _catalog_model(catalog, model_id) or {}
    remote_max = _positive_int(remote.get("maxOutput") or remote.get("maxOutputTokens"))
    if remote_max is not None:
        return remote_max
    return _positive_int((FALLBACK_INDEX.get(model_id) or {}).get("maxOutput"))


def build_payload(body: dict, model_id: str, catalog: Any) -> dict:
    """构造上游请求体（字段名与 ``loomy-adapter.ts`` 的 ``buildBody`` 一致）。

    ⚠️ ``reasoning_effort`` **只在该模型的档位表内存在时**才下发 —— 实测传
    ``reasoning_effort`` / ``reasoningEffort`` / ``thinking`` 三种名字服务端**都回 200**
    （对未知字段静默忽略），故不能靠状态码试错，只能按远端自己的命名下发；
    校验不过时**静默不下发**（退回服务端默认档），而不是发一个可能被拒的值。
    """
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": serialize_messages(body.get("messages")),
        "stream": True,
    }
    max_tokens = max_tokens_for(model_id, body, catalog)
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    temperature = body.get("temperature")
    if isinstance(temperature, (int, float)) and not isinstance(temperature, bool):
        payload["temperature"] = temperature
    stop = body.get("stop")
    if isinstance(stop, list) and stop:
        payload["stop"] = stop
    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        payload["tools"] = tools
    requested = body.get("reasoning_effort")
    if isinstance(requested, str) and requested != "" and requested in efforts_for(model_id, catalog):
        payload["reasoning_effort"] = requested
    return payload


def _status_code(status: int) -> str:
    """HTTP 状态 → 失败码（仅用于「根本不是 SSE」的响应）。"""
    if status in (401, 403):
        return CODE["credential"]
    if status == 429:
        return CODE["quota"]
    if status >= 500:
        return CODE["server"]
    return CODE["client"]


def _usage_chunk(raw: Any) -> dict:
    """把 ``read_stream`` 汇总的 usage 投影成内部 ``usage`` chunk。

    ``inputTokens`` 只含**未缓存**输入（``map_usage`` 的语义），缓存命中单列
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
    if number("cacheWriteTokens") > 0:
        out["cacheWriteTokens"] = number("cacheWriteTokens")
    return out


def _finish_of(state: dict, blocks: int) -> dict:
    """由 ``read_stream`` 的汇总状态算出 ``finish`` 的 reason。

    - 工具参数残缺（``brokenToolCall``）→ ``max-tokens``（报 ``tool-calls`` 会让 harness
      执行半截 JSON 参数，模型随后陷入重试循环）；
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
    """POST 一轮 ``{API_BASE}/chat/completions`` 并以内部 chunk 产出。

    SSE 的逐帧解析与块组装交给 ``read_stream``（``wire="chat"``）：思考是
    ``delta.reasoning_content`` → ``reasoning-delta``，工具调用按 ``index`` 合并 →
    ``tool-call-delta``（带 ``index/id/name/argumentsDelta``），``finish_reason`` 映射为
    ``stop`` / ``tool-calls`` / ``max-tokens``，收尾由本函数补 ``usage`` 与 ``finish``。

    401/403 时 Loomy **没有续期端点**，故只做一次有效性探测（:func:`probe_credential`）：
    探测不通过会抛「登录已失效，请重新短信登录」，而**不是**假装续期后重发。

    ``catalog`` 用于补齐思考档位与输出额度（``fetch_models`` 的结果）；``on_refresh``
    在本渠道**永远不会被调用**（无 refresh 端点），保留形参仅为对齐渠道约定。
    """
    del on_refresh
    model_id = str(body.get("model") or "")
    payload = build_payload(body, model_id, catalog)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    url = f"{API_BASE}{CHAT_PATH}"
    token = str((credential or {}).get("access_token") or "")
    if token == "":
        raise UpstreamError("loomy: no usable credential; log in first", CODE["credential"])

    channel = create_channel()
    client = await get_client()

    def forward(text: str) -> None:
        """送入内部流；SSE 里内嵌的业务错误帧如实报错（HTTP 200 陷阱）。"""
        try:
            frame = json.loads(text)
        except ValueError:
            channel.push(text)
            return
        if is_error_frame(frame):
            raise _business_error(200, frame.get("code"),
                                  frame.get("desc") or frame.get("message") or "")
        channel.push(text)

    async def produce() -> None:
        response = None
        try:
            response = await client.send(
                client.build_request("POST", url, headers=chat_headers(token), content=data), stream=True)
            if response.status_code in (401, 403):
                await response.aread()
                await response.aclose()
                response = None
                # ⚠️ 没有 refresh 端点：只能探测。探测通过说明凭据仍有效（多半是服务端抖动），
                # 原样重发一次；不通过则 probe_credential 抛出的凭据错误直接上抛。
                await probe_credential({"access_token": token})
                response = await client.send(
                    client.build_request("POST", url, headers=chat_headers(token), content=data), stream=True)
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                raise UpstreamError(f"loomy: HTTP {response.status_code} {text[:200]}",
                                    _status_code(response.status_code), status=response.status_code)
            head = await read_head(response.aiter_bytes(), 4096, STREAM_TIMEOUT_S)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("loomy: empty model response body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), forward, STREAM_TIMEOUT_S)
            else:
                text = (await _read_remainder(head)).decode("utf-8", "replace")
                try:
                    parsed = json.loads(text)
                except ValueError:
                    raise UpstreamError("loomy: unexpected non-stream response", CODE["server"])
                if is_error_frame(parsed):
                    raise _business_error(200, parsed.get("code"),
                                          parsed.get("desc") or parsed.get("message") or "")
                if isinstance(parsed, dict) and parsed.get("error"):
                    raise UpstreamError(f"loomy: {parsed['error']}", CODE["server"])
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


# ── 产品配置与兼容别名 ─────────────────────────────────────────────────────

#: 管理器用模块级 ``CONTEXT_WINDOWS`` 补目录条目的 ``contextWindow``（上面已定义）。
PRODUCT: dict[str, Any] = {
    "id": CHANNEL_ID,
    "displayName": DISPLAY_NAME,
    "apiBase": API_BASE,
    "accountBase": ACCOUNT_BASE,
    "accessKeyId": ACCESS_KEY_ID,
    "appId": APP_ID,
    "defaultCredentialRef": DEFAULT_CREDENTIAL_REF,
    "fallbackModels": FALLBACK_MODELS,
}

#: 登录形态：短信验证码（**分步**）。
LOGIN_MODE = "sms"

#: 显式声明「本渠道只提供分步登录」——**不要**在别处给本模块挂 ``run_login``：
#: 管理器一旦发现 ``run_login`` 就会走「后台任务 + 轮询」那条路，短信登录会变成
#: 「没地方输入验证码」的死胡同。
HAS_MULTI_STEP_LOGIN = True
