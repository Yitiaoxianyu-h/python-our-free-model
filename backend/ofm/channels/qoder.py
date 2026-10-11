"""Qoder（国际版 ``qoder``）与 Qoder 中国版（``qodercn``）的**共用**实现。

移植自原版 channel-pack 的 ``qoder.ts`` / ``qoder-oauth.ts`` / ``qoder-auth.ts`` /
``qoder-adapter.ts`` / ``qoder-envelope.ts`` / ``qoder-product.ts`` / ``qoder-wasm.ts``。
``qodercn`` 只有「域名 / client_id / 模型表」三处不同，故 ``qodercn.py`` 直接 import
本模块并复用同一套实现（同属一家产品，不复制实现文件）。

## 协议要点（逐条对照原版）

- **登录**：PKCE 设备码轮询。打开 ``{authBase}/device/selectAccounts?challenge=…``，
  然后轮询 ``{openApiBase}/api/v1/deviceToken/poll?nonce=…&verifier=…``，
  ``404`` = 用户还没授权（**继续轮询**），1s 间隔、5 分钟超时。
  ``machine_id`` 由本插件生成并**随凭据持久化**（不是硬件指纹）。
- **续期**：``POST {openApiBase}/api/v1/deviceToken/refresh``，
  体为 ``{refresh_token, machine_id}``；401/403 → 凭据失效（终态）。
- **用户信息**：``GET {openApiBase}/api/v1/userinfo``（展示名 ``name`` 与 ``id``）。
- **推理**：走**加密端点** ``POST {encryptedInferBase}/algo/api/v2/service/pro/sse/agent_chat_generation``
  （``?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1``）。
  请求体由 `qoder-auth-wasm.wasm` 加密，``Authorization`` 头是 WASM 生成的
  ``Bearer COSY.<载荷>.<签名>`` —— **必须原样透传**，用普通 ``Bearer <token>``
  覆盖会被 403 ``Signature invalid``。
  响应是 SSE 但多一层信封（``{"body":"<标准 OpenAI 帧>"}``），内层**未加密**，只剥信封。
- **模型目录**：原版**不发**远端模型列表请求（该端点需要 WASM 签名），恒用兜底表；
  本移植沿用该口径，另外**尽力**读取本机 ``~/.qoder/.models/<uid>/catalog-v6``
  （WASM 的 ``model_cache_decrypt``）作核对与补充。

## ⚠️ WASM 与「纯 Python 复刻」的结论（实测，2026 年本机）

``qoder-auth-wasm.wasm`` 是 **wasm-bindgen 产物**，其 import 全部来自
``./qoder_auth_wasm_bg.js``（对象堆、字符串读写、``getRandomValues`` 等）。

**结论一：该 WASM 可以在 Python 里直接驱动，不需要 JS glue。**
用 ``wasmtime`` 按 wasm-bindgen ABI 重建那层 glue（对象堆 + ``__wbindgen_add_to_stack_pointer``
+ 返回值布局）后，实测在本机成功产出：

- ``generate_runtime_auth_fields`` → ``{encrypt_user_info, key}``；
- ``qodercontext_new`` → 上下文指针；
- ``qodercontext_prepareInferRequest`` → ``requestresult_headers`` 里带着
  ``Authorization: Bearer COSY.<payload>.<sig>``（内含 ``Cosy-Key`` / ``Cosy-User`` /
  ``Cosy-Date`` / ``Cosy-MachineId`` 等）、``requestresult_url``、``requestresult_body``
  （加密后的密文）。

**结论二：签名本身无法在不逆向 WASM 的前提下用纯 Python 复刻。**
对实测样本做过尝试（``md5``/``hmac-md5``/``hmac-sha256`` 截断，分别以
``BASIC`` 段、明文 JSON、``info`` 字段、``Cosy-Key`` 作密钥，多种拼接顺序），
**32 位十六进制签名一个都不匹配**；而 ``Cosy-Key`` 是运行时随机材料化的密钥，
其派生链同样在 WASM 内部。故本模块**不编造签名算法**：能驱动 WASM 就用 WASM，
不能驱动就明确报 ``NotImplementedError``。

**降级路径**：本仓库 ``backend/.venv`` 里**没有** ``wasmtime``，
且 ``qoder-auth-wasm.wasm`` 位于 ``old/`` 目录（属源码树，不在运行时数据目录）。
因此在本仓库当前依赖下，:func:`stream` 会抛
``NotImplementedError``（原因见 :func:`_signer_available` 的说明）；
装上 ``wasmtime`` 并把 wasm 放到 ``OFM_QODER_WASM`` 指向的路径即可启用。
``run_login`` / ``refresh_credential`` / ``fetch_models`` **不依赖 WASM**，恒可用。

## 中国版与国际版的差异（``qoder-product.ts``）

| 项 | qoder（国际版） | qodercn（中国版） |
|---|---|---|
| authBase | ``https://qoder.com`` | ``https://qoder.cn`` |
| openApiBase | ``https://openapi.qoder.sh`` | ``https://openapi.qoder.com.cn`` |
| 加密推理 host | ``https://api2.qoder.sh`` | ``https://gateway.qoder.com.cn`` |
| 公开 OpenAI 兼容端点 | ``https://api2-v2.qoder.sh`` | **无**（实测 503，设备码目录 key 本就只认加密端点） |
| client_id | ``e883ade2-…`` | ``732aef47-…`` |
| 凭据 ref | ``QODER_ACCESS_TOKEN`` | ``QODERCN_ACCESS_TOKEN`` |
| 模型表 | 17 条 | 14 条（有 CN 独有项，见 ``FALLBACK_MODELS_CN``） |
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import read_stream

CHANNEL_ID = "qoder"

# ── 协议常量（qoder.ts / qoder-oauth.ts） ───────────────────────────────────

#: 授权页路径（挂 ``authBase``）。
DEVICE_SELECT_PATH = "/device/selectAccounts"
#: 轮询取 token 路径（挂 ``openApiBase``）。⚠️ 不是 authBase：写错 host 登录永远失败。
DEVICE_TOKEN_POLL_PATH = "/api/v1/deviceToken/poll"
#: 续期路径（挂 ``openApiBase``）。
DEVICE_TOKEN_REFRESH_PATH = "/api/v1/deviceToken/refresh"
#: 用户信息路径（挂 ``openApiBase``）。
USERINFO_PATH = "/api/v1/userinfo"
#: **公开** OpenAI 兼容端点路径（只认通用名 ``qwen-flash``，**不认目录 key**）。
PUBLIC_CHAT_PATH = "/model/v1/chat/completions"
#: **加密**端点路径（认目录 key；请求体由 WASM 加密）。
ENCRYPTED_CHAT_PATH = "/algo/api/v2/service/pro/sse/agent_chat_generation"
#: 加密端点的固定 query。
ENCRYPTED_CHAT_QUERY = {"FetchKeys": "llm_model_result", "AgentId": "agent_common", "Encode": "1"}

#: 单次 HTTP 请求超时（毫秒 → 秒）。
REQUEST_TIMEOUT_S = 30.0
#: 登录等待总超时（源码 ``L_a = 3e5``）。
LOGIN_TIMEOUT_S = 300.0
#: 轮询间隔（源码 ``Djr = 1e3``）。
POLL_INTERVAL_S = 1.0
#: 轮询连续网络失败上限（源码 ``H_a = 3``；本实现放宽到 5 以容忍抖动）。
POLL_MAX_FAILURES = 5
#: 推理流：等待首字节与两次 chunk 之间的静默上限（原版可经环境变量覆盖，默认 120s）。
STREAM_TIMEOUT_S = 120.0
#: 客户端版本（写进 ``Cosy-Version``，并参与签名载荷）。
COSY_VERSION = "1.1.49"

#: PKCE 字符集：RFC 7636 的 unreserved 集合（66 个字符，与源码 ``Y_a()`` 一致）。
PKCE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

#: 本机目录缓存的加密文件名（``~/.qoder/.models/<uid>/catalog-v6``）。
MODEL_CACHE_FILE = "catalog-v6"

#: 思考档位白名单（客户端常量 ``Qj``）；不在表里的会被上游**静默丢弃**。
EFFORT_WHITELIST = ("none", "low", "medium", "high", "xhigh", "max")
#: 档位别名（客户端 ``_lc``）：``disabled``/``off`` 归一为 ``none``。
EFFORT_ALIASES = {"disabled": "none", "off": "none"}
#: 官方 UI 的档位中文名（asar i18n ``settings.efforts``）。
EFFORT_NAMES = {"none": "关闭思考", "minimal": "最小", "low": "低", "medium": "中",
                "high": "高", "xhigh": "极高", "max": "最大"}

#: 目录 key → 该端点的 ``business.type``（服务端按它选路由池）。
#: ⚠️ 缺 ``business`` 时 ``qfmodel`` 会被路由到故障节点（原版实测）。
BUSINESS = {"type": "agent"}

#: 默认单次输出上限（原版兜底表未逐条给出时使用）。
DEFAULT_MAX_OUTPUT = 32768


# ── 产品配置（qoder-product.ts 的 ``QODER``） ───────────────────────────────

#: 国际版兜底模型表（实测 2026-09-21 对照本机 ``catalog-v6``；17 条）。
#: ``contextWindow`` 取目录**档位表的最大档**（不是 ``max_input_tokens``）。
FALLBACK_MODELS: list[dict] = [
    {"id": "auto", "name": "Auto", "contextWindow": 200_000, "vision": True, "reasoning": False,
     "priceFactor": 0.5},
    {"id": "ultimate", "name": "Ultimate", "contextWindow": 1_000_000, "vision": True, "reasoning": True,
     "priceFactor": 2, "reasoningEfforts": ["xhigh", "high", "low", "max", "medium"],
     "defaultReasoningEffort": "high", "canDisableThinking": True},
    {"id": "performance", "name": "Performance", "contextWindow": 1_000_000, "vision": True,
     "reasoning": False, "priceFactor": 1.1,
     "reasoningEfforts": ["xhigh", "high", "low", "max", "medium"], "defaultReasoningEffort": "medium",
     "canDisableThinking": True},
    {"id": "efficient", "name": "Efficient", "contextWindow": 1_000_000, "vision": True, "reasoning": False,
     "priceFactor": 0.3},
    {"id": "smodel", "name": "Sonus", "contextWindow": 1_000_000, "vision": True, "reasoning": True,
     "priceFactor": 8, "reasoningEfforts": ["xhigh", "high", "low", "max", "medium"],
     "defaultReasoningEffort": "high"},
    {"id": "cmodel", "name": "Cantus", "contextWindow": 1_000_000, "vision": True, "reasoning": True,
     "priceFactor": 4, "reasoningEfforts": ["xhigh", "high", "low", "max", "medium"],
     "defaultReasoningEffort": "high"},
    # 免费额度模型（目录 ``is_free=true``）。⚠️ ``priceFactor=0`` 是**免费**，不是缺失。
    {"id": "qmodel_38max", "name": "Qwen3.8-Max", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "free": True, "priceFactor": 0.2,
     "reasoningEfforts": ["xhigh", "low", "medium"], "defaultReasoningEffort": "xhigh",
     "canDisableThinking": True},
    {"id": "qfmodel", "name": "Qwen3.8-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "free": True, "priceFactor": 0,
     "reasoningEfforts": ["xhigh", "low", "medium"], "defaultReasoningEffort": "medium",
     "canDisableThinking": True},
    # ⚠️ 这两个目录里**只有 ``disabled`` + ``enabled.is_default``，没有 ``efforts``**
    # —— 官方只提供「关闭思考」一个选项，故 ``reasoningEfforts`` 为空。
    {"id": "qmodel_latest", "name": "Qwen3.7-Max", "contextWindow": 1_000_000, "vision": True,
     "reasoning": False, "priceFactor": 0.1, "canDisableThinking": True},
    {"id": "qmodel", "name": "Qwen3.7-Plus", "contextWindow": 1_000_000, "vision": True,
     "reasoning": False, "priceFactor": 0.04, "canDisableThinking": True},
    {"id": "kmodel_latest", "name": "Kimi-K3", "contextWindow": 1_000_000, "vision": True,
     "reasoning": False, "priceFactor": 1.4, "reasoningEfforts": ["high", "low", "max"],
     "defaultReasoningEffort": "max"},
    {"id": "kmodel", "name": "Kimi-K2.8-Preview", "contextWindow": 1_000_000, "vision": True,
     "reasoning": False, "priceFactor": 0.8, "reasoningEfforts": ["high", "low", "max"],
     "defaultReasoningEffort": "max"},
    {"id": "gmodel", "name": "GLM-5.3", "contextWindow": 1_000_000, "vision": True, "reasoning": True,
     "priceFactor": 0.8, "reasoningEfforts": ["high", "low", "max"], "defaultReasoningEffort": "max"},
    {"id": "gfmodel", "name": "GLM-5.3-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.1, "reasoningEfforts": ["high", "max"],
     "defaultReasoningEffort": "max"},
    {"id": "dmodel", "name": "DeepSeek-V4-Pro", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.5, "reasoningEfforts": ["high", "max"],
     "defaultReasoningEffort": "max", "canDisableThinking": True},
    {"id": "dfmodel", "name": "DeepSeek-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.1, "reasoningEfforts": ["high", "max", "low"],
     "defaultReasoningEffort": "max", "canDisableThinking": True},
    {"id": "mmodel", "name": "MiniMax-M3", "contextWindow": 1_000_000, "vision": True,
     "reasoning": False, "priceFactor": 0.2},
]

#: 中国版兜底模型表（14 条）。与国际版的差异逐条标注。
FALLBACK_MODELS_CN: list[dict] = [
    {"id": "auto", "name": "Auto", "contextWindow": 200_000, "vision": True, "reasoning": True,
     "priceFactor": 0.5},
    {"id": "qmodel_38max", "name": "Qwen3.8-Max", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "free": True, "priceFactor": 0.2,
     "reasoningEfforts": ["xhigh", "low", "medium"], "defaultReasoningEffort": "medium",
     "canDisableThinking": True},
    {"id": "qfmodel", "name": "Qwen3.8-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "free": True, "priceFactor": 0,
     "reasoningEfforts": ["xhigh", "low", "medium"], "defaultReasoningEffort": "medium",
     "canDisableThinking": True},
    {"id": "qmodel_latest", "name": "Qwen3.7-Max", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.1, "canDisableThinking": True},
    {"id": "qmodel", "name": "Qwen3.7-Plus", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.04, "canDisableThinking": True},
    # CN 独有：Qwen3.7-Flash（国际版目录无此 key；目录里**完全没有 thinking_config**）。
    {"id": "q37fmodel", "name": "Qwen3.7-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.1},
    {"id": "dmodel", "name": "DeepSeek-V4-Pro", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.5, "reasoningEfforts": ["high", "max"],
     "defaultReasoningEffort": "max", "canDisableThinking": True},
    # ⚠️ CN 的 ``is_reasoning`` 为 false（国际版为 true），故不声明 reasoning。
    {"id": "dfmodel", "name": "DeepSeek-Flash", "contextWindow": 1_000_000, "vision": True,
     "priceFactor": 0.1, "reasoningEfforts": ["high", "max", "low"], "defaultReasoningEffort": "max",
     "canDisableThinking": True},
    {"id": "gmodel", "name": "GLM-5.3", "contextWindow": 1_000_000, "vision": True, "reasoning": True,
     "priceFactor": 0.8, "reasoningEfforts": ["high", "low", "max"], "defaultReasoningEffort": "max"},
    {"id": "gfmodel", "name": "GLM-5.3-Flash", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.1, "reasoningEfforts": ["high", "max"],
     "defaultReasoningEffort": "max"},
    # CN 独有：GLM-5.2（国际版目录无此 key）。
    {"id": "gm51model", "name": "GLM-5.2", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.6, "reasoningEfforts": ["high", "max"],
     "defaultReasoningEffort": "max", "canDisableThinking": True},
    {"id": "kmodel_latest", "name": "Kimi-K3", "contextWindow": 1_000_000, "vision": True,
     "priceFactor": 1.4, "reasoningEfforts": ["high", "low", "max"], "defaultReasoningEffort": "max"},
    {"id": "kmodel", "name": "Kimi-K2.8-Preview", "contextWindow": 1_000_000, "vision": True,
     "reasoning": True, "priceFactor": 0.8, "reasoningEfforts": ["high", "low", "max"],
     "defaultReasoningEffort": "max"},
    # ⚠️ 版本是 M2.7（国际版 M3），``is_vl`` 为 false，且档位表只有 200K 一档。
    {"id": "mmodel", "name": "MiniMax-M2.7", "contextWindow": 200_000, "priceFactor": 0.2},
]

#: 国际版产品配置（``qoder-product.ts`` 的 ``QODER``）。
PRODUCT: dict[str, Any] = {
    "id": "qoder",
    "displayName": "Qoder",
    "authBase": "https://qoder.com",
    "openApiBase": "https://openapi.qoder.sh",
    # 推理走独立的 model server host（源码 ``Sja.prod``）；
    # ⚠️ 不是 ``environments.prod.inferBaseUrl``（那是 ``api2.qoder.sh``）。
    "publicInferBase": "https://api2-v2.qoder.sh",
    # 加密端点（``agent_chat_generation``）所在 host —— 写错会 404。
    "encryptedInferBase": "https://api2.qoder.sh",
    # ⚠️ prod 用 ``clientId``（源码 ``J_a``）；用成 ``testClientId``（``G_a``）
    # 会在授权回调阶段被拒（页面报「参数无效」）。
    "clientId": "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb",
    "testClientId": "e93fe488-5778-4c35-a6fc-0f54ed7b3139",
    "clientMetadata": {"client_type": "5", "business_product": "cli",
                       "business_type": "agent", "scene": "assistant"},
    "userAgentPrefix": "qoder",
    "credentialRef": "QODER_ACCESS_TOKEN",
    "fallbackModels": FALLBACK_MODELS,
}

#: 中国版产品配置（``qoder-product.ts`` 的 ``QODER_CN``）。
PRODUCT_CN: dict[str, Any] = {
    "id": "qodercn",
    "displayName": "Qoder (中国版)",
    "authBase": "https://qoder.cn",
    "openApiBase": "https://openapi.qoder.com.cn",
    # ⚠️ CN **没有**可用的公开 OpenAI 兼容端点（实测 gateway / openapi 都回 503），
    # 这里填同值仅表示「没有独立公开端点」，**不要**据此发请求。
    "publicInferBase": "https://gateway.qoder.com.cn",
    "encryptedInferBase": "https://gateway.qoder.com.cn",
    # CN 的 ``authClientIds.test`` 与 ``prod`` 同值（不存在国际版读反的风险）。
    "clientId": "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa",
    "testClientId": "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa",
    "clientMetadata": {"client_type": "5", "business_product": "cli",
                       "business_type": "agent", "scene": "assistant"},
    "userAgentPrefix": "qoder",
    "credentialRef": "QODERCN_ACCESS_TOKEN",
    "fallbackModels": FALLBACK_MODELS_CN,
}

FALLBACK_INDEX: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS}
FALLBACK_INDEX_CN: dict[str, dict] = {model["id"]: model for model in FALLBACK_MODELS_CN}
CONTEXT_WINDOWS: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS}
CONTEXT_WINDOWS_CN: dict[str, int] = {model["id"]: model["contextWindow"] for model in FALLBACK_MODELS_CN}

#: ``session_type``。官方源码：``r0() ? l7A : swe``。
#: 国际版客户端是 ``qodercli``（``swe``），中国版客户端是 ``qoder_work``（``l7A``）。
#: ⚠️ 原版 adapter **两边都没传** ``sessionType``，于是两边都用 WASM 的默认值 ``qodercli``。
#: 本移植沿用原版行为（保持与已移植代码逐字节一致），并把值提成常量便于单独调整。
SESSION_TYPE = "qodercli"


def _product(product: dict | None = None) -> dict:
    """取产品配置（默认国际版）。"""
    return product if product is not None else PRODUCT


def _models(product: dict) -> list[dict]:
    return product.get("fallbackModels") or FALLBACK_MODELS


def _index(product: dict) -> dict[str, dict]:
    models = _models(product)
    return {model["id"]: model for model in models}


# ── PKCE / 设备会话（qoder.ts） ─────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_pkce() -> tuple[str, str]:
    """生成 PKCE ``(verifier, challenge)``。

    verifier 长度取 ``43 + floor(86 * random)``（源码 ``43 + Math.floor(86*Math.random())``）；
    challenge 是 ``base64url(sha256(verifier))`` 且**去掉 padding**（带 ``=`` 服务端会校验失败）。
    """
    length = 43 + int(86 * secrets.randbelow(1 << 30) / (1 << 30))
    raw = secrets.token_bytes(length)
    verifier = "".join(PKCE_ALPHABET[byte % len(PKCE_ALPHABET)] for byte in raw)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_auth_url(verifier: str, challenge: str, nonce: str, machine_id: str, product: dict | None = None) -> str:
    """构造浏览器授权 URL（``{authBase}/device/selectAccounts?...``）。"""
    from urllib.parse import urlencode

    config = _product(product)
    query = urlencode({
        "challenge": challenge,
        "challenge_method": "S256",
        "nonce": nonce,
        "machine_id": machine_id,
        "client_id": config["clientId"],
    })
    return f"{config['authBase']}{DEVICE_SELECT_PATH}?{query}"


def build_poll_url(verifier: str, nonce: str, product: dict | None = None) -> str:
    """构造轮询 URL。

    ⚠️ 挂 **``openApiBase``**，不是 ``authBase``：实测 ``qoder.com`` 的该路径返回 401，
    而 ``openapi.qoder.sh`` 返回 404（= 无待授权会话，应继续轮询）。
    """
    from urllib.parse import urlencode

    config = _product(product)
    query = urlencode({"nonce": nonce, "verifier": verifier, "challenge_method": "S256"})
    return f"{config['openApiBase']}{DEVICE_TOKEN_POLL_PATH}?{query}"


# ── 凭据（qoder.ts） ───────────────────────────────────────────────────────

def read_string(source: Any, keys: tuple[str, ...]) -> str:
    """读第一个非空字符串字段（容忍缺失与非字符串）。"""
    if not isinstance(source, dict):
        return ""
    for key in keys:
        value = source.get(key)
        if isinstance(value, str) and value != "":
            return value
    return ""


def read_timestamp(value: Any) -> int | None:
    """把时间值解析成**毫秒**时间戳；无法解析返回 ``None``（绝不返回 0）。

    兼容数字（10 位视为秒、13 位视为毫秒）与 ISO 字符串。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value > 0:
        return int(round(value * 1000)) if value < 1e12 else int(round(value))
    if isinstance(value, str) and value != "":
        text = value.strip()
        if re.fullmatch(r"-?\d+(\.\d+)?", text):
            return read_timestamp(float(text))
        try:
            from datetime import datetime

            return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            return None
    return None


def parse_token_payload(value: Any) -> dict:
    """解析 token 响应。

    登录响应用 ``token``、续期响应用 ``device_token``（字段名不同，故都接受）；
    ``user_id`` / ``user_name`` 也一并读出（**加密推理需要 uid**）。
    """
    if not isinstance(value, dict):
        return {"accessToken": ""}
    payload: dict[str, Any] = {
        "accessToken": read_string(value, ("token", "device_token", "access_token")),
    }
    refresh = read_string(value, ("refresh_token", "refreshToken"))
    if refresh:
        payload["refreshToken"] = refresh
    expires = read_timestamp(value.get("expires_at", value.get("expiresAt")))
    if expires is not None:
        payload["expiresAt"] = expires
    refresh_expires = read_timestamp(value.get("refresh_token_expires_at", value.get("refreshTokenExpiresAt")))
    if refresh_expires is not None:
        payload["refreshTokenExpiresAt"] = refresh_expires
    uid = read_string(value, ("user_id", "userId"))
    if uid:
        payload["uid"] = uid
    name = read_string(value, ("user_name", "userName"))
    if name:
        payload["userName"] = name
    return payload


def build_credential(payload: dict, *, machine_id: str, nickname: str | None = None,
                     uid: str | None = None) -> dict:
    """把 token 载荷变成凭据 dict。

    ``security_oauth_token`` 与 ``access_token`` **双写同值**（客户端取用顺序是
    ``security_oauth_token ?? access_token``）；``machine_id`` 必须持久化（续期要用）。
    """
    token = payload.get("accessToken") or ""
    credential: dict[str, Any] = {
        "security_oauth_token": token,
        "access_token": token,
        "machine_id": machine_id,
    }
    if payload.get("refreshToken"):
        credential["refresh_token"] = payload["refreshToken"]
    if payload.get("expiresAt") is not None:
        credential["expire_time"] = payload["expiresAt"]
    if payload.get("refreshTokenExpiresAt") is not None:
        credential["refresh_token_expire_time"] = payload["refreshTokenExpiresAt"]
    resolved_uid = uid or payload.get("uid") or ""
    if resolved_uid:
        credential["uid"] = resolved_uid
    resolved_name = nickname or payload.get("userName") or ""
    if resolved_name:
        credential["nickname"] = resolved_name
    return credential


def bearer_token(credential: dict) -> str:
    """取 Bearer 令牌（``security_oauth_token`` 优先，与源码一致）。"""
    token = credential.get("security_oauth_token")
    if isinstance(token, str) and token != "":
        return token
    value = credential.get("access_token")
    return value if isinstance(value, str) else ""


def credential_expires_at_ms(credential: dict) -> int | None:
    expires = credential.get("expire_time")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        return None
    return int(expires)


def is_expired(credential: dict, now_ms: int | None = None) -> bool:
    """访问令牌是否过期。无过期时间时保守视为未过期（交给服务端 401 判定）。"""
    expires = credential_expires_at_ms(credential)
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    return expires is not None and expires <= now


def is_refreshable(credential: dict) -> bool:
    """是否可静默续期（判据是「有 refresh_token」，与是否过期无关）。"""
    token = credential.get("refresh_token")
    return isinstance(token, str) and token != ""


def apply_refresh(credential: dict, payload: dict) -> dict:
    """用续期结果覆盖旧凭据，**保留** ``machine_id`` / ``uid`` / ``nickname``。

    它们不在续期响应里：丢了会让下一次续期缺设备标识、或让加密推理缺 uid；
    续期响应若不带新 ``refresh_token``，沿用旧的（避免把可续期凭据变成不可续期）。
    """
    next_credential = build_credential(
        payload,
        machine_id=credential.get("machine_id") or "",
        nickname=credential.get("nickname"),
        uid=credential.get("uid"),
    )
    if "refresh_token" not in next_credential and credential.get("refresh_token"):
        next_credential["refresh_token"] = credential["refresh_token"]
    if "uid" not in next_credential and credential.get("uid"):
        next_credential["uid"] = credential["uid"]
    if "nickname" not in next_credential and credential.get("nickname"):
        next_credential["nickname"] = credential["nickname"]
    return next_credential


# ── 通用请求头（qoder.ts / qoder-auth.ts） ─────────────────────────────────

def _user_agent(product: dict) -> str:
    return f"{product['userAgentPrefix']}/1.0.0"


def control_headers(product: dict) -> dict[str, str]:
    """控制面（轮询 / 续期 / userinfo）请求头。"""
    return {"Accept": "application/json", "User-Agent": _user_agent(product)}


def _open_external(url: str) -> bool:
    """用系统默认浏览器打开 URL；永不抛出。"""
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


async def _json_body(response: httpx.Response) -> Any:
    text = (await response.aread()).decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


# ── 登录（qoder-oauth.ts 的 runQoderLoginFlow） ────────────────────────────

async def _poll_device_token(verifier: str, nonce: str, *, product: dict,
                             timeout_s: float, poll_interval_s: float) -> dict:
    """轮询直到拿到 token。

    **404 表示「用户尚未完成授权」，必须继续轮询**；其它非 2xx 立即抛错
    （那是服务端异常，不是「等用户」）。网络失败容忍 :data:`POLL_MAX_FAILURES` 次。
    """
    client = await get_client()
    url = build_poll_url(verifier, nonce, product)
    deadline = time.monotonic() + timeout_s
    failures = 0
    while time.monotonic() < deadline:
        try:
            response = await client.get(url, headers=control_headers(product), timeout=REQUEST_TIMEOUT_S)
            failures = 0
            if response.status_code == 404:
                await asyncio.sleep(poll_interval_s)
                continue
            if response.status_code >= 400:
                raise UpstreamError(
                    f"{product['id']}: 登录服务返回异常（HTTP {response.status_code}）",
                    CODE["server"], status=response.status_code)
            payload = parse_token_payload(await _json_body(response))
            if payload["accessToken"]:
                return payload
            # 2xx 但尚无 token：同样继续轮询
            await asyncio.sleep(poll_interval_s)
        except UpstreamError:
            raise
        except (httpx.HTTPError, OSError) as error:
            failures += 1
            if failures >= POLL_MAX_FAILURES:
                raise UpstreamError(
                    f"{product['id']}: 无法连接登录服务（连续 {failures} 次失败）：{error}",
                    CODE["transport"])
            await asyncio.sleep(poll_interval_s)
    raise UpstreamError(f"{product['id']}: 登录等待已超时，请重新发起登录", CODE["timeout"])


async def fetch_userinfo(credential: dict, product: dict | None = None) -> dict | None:
    """``GET {openApiBase}/api/v1/userinfo``；失败返回 ``None``（不抛错）。

    两个用途：
    1. 取展示名 ``name``（设备码轮询响应里**没有** ``user_name``，这是唯一可靠来源；
       原版记录过「登录后名字都是 ``qoder-xxxx``」的真实缺陷）；
    2. 取用户 id（``id`` / ``uid``）—— **加密推理必需**，缺它 WASM 会产出签名无效的请求。
    """
    config = _product(product)
    try:
        client = await get_client()
        response = await client.get(f"{config['openApiBase']}{USERINFO_PATH}",
                                    headers={**control_headers(config),
                                             "Authorization": f"Bearer {bearer_token(credential)}"},
                                    timeout=REQUEST_TIMEOUT_S)
        if response.status_code >= 400:
            return None
        body = await _json_body(response)
        return body if isinstance(body, dict) else None
    except Exception:  # noqa: BLE001
        return None


async def run_login(*, open_browser: bool = True, timeout_s: float = LOGIN_TIMEOUT_S,
                    poll_interval_s: float = POLL_INTERVAL_S, product: dict | None = None,
                    print_fn: Callable[[str], None] = print) -> dict:
    """完整登录：生成 PKCE 设备会话 → 打开授权页 → 轮询 → 补 userinfo → 返回凭据。

    与 CodeArts / LobsterAI 不同，Qoder **不起本地回调服务器**：登录靠轮询设备码端点。

    **不依赖 WASM**，故在任何依赖组合下都可用。
    """
    config = _product(product)
    verifier, challenge = create_pkce()
    nonce = str(uuid.uuid4())
    machine_id = str(uuid.uuid4())
    login_url = build_auth_url(verifier, challenge, nonce, machine_id, config)
    if open_browser:
        if not _open_external(login_url):
            print_fn(f"[{config['id']}] 无法自动打开浏览器，请手动访问：{login_url}")
    else:
        print_fn(f"[{config['id']}] 请在浏览器中打开：{login_url}")

    payload = await _poll_device_token(verifier, nonce, product=config,
                                       timeout_s=timeout_s, poll_interval_s=poll_interval_s)
    if not payload["accessToken"]:
        raise UpstreamError(f"{config['id']}: 登录响应缺少访问令牌", CODE["credential"])
    credential = build_credential(payload, machine_id=machine_id)
    credential["login_url"] = login_url

    # 补一次 userinfo：拿展示名与 uid（两者都不是登录响应的可靠来源）。
    info = await fetch_userinfo(credential, config)
    if info is not None:
        name = info.get("name")
        if isinstance(name, str) and name.strip():
            credential["nickname"] = name.strip()
        uid = read_string(info, ("id", "uid", "user_id"))
        if uid:
            credential["uid"] = uid
    return credential


# ── 续期（qoder-auth.ts 的 refreshCredential） ─────────────────────────────

async def refresh_credential(credential: dict, *, product: dict | None = None) -> dict:
    """``POST {openApiBase}/api/v1/deviceToken/refresh``，体为 ``{refresh_token, machine_id}``。

    终态：HTTP 401/403 → :data:`CODE` 的凭据错误（调用方应停止续期）；
    其余（网络抖动 / 5xx / 429）→ ``CODE["server"]``（可重试）。

    **不依赖 WASM**。
    """
    config = _product(product)
    if not is_refreshable(credential):
        raise UpstreamError(f"{config['id']}: 无 refresh_token，请重新登录", CODE["credential"])
    body = {"refresh_token": credential.get("refresh_token") or "",
            "machine_id": credential.get("machine_id") or ""}
    client = await get_client()
    try:
        response = await client.post(f"{config['openApiBase']}{DEVICE_TOKEN_REFRESH_PATH}",
                                     headers={**control_headers(config), "Content-Type": "application/json"},
                                     content=json.dumps(body), timeout=REQUEST_TIMEOUT_S)
    except (httpx.HTTPError, OSError) as error:
        # 传输层失败**不能**判为终态 —— 网络抖动不该让用户重新登录。
        raise UpstreamError(f"{config['id']}: 续期网络失败：{error}", CODE["transport"])
    if response.status_code in (401, 403):
        raise UpstreamError(f"{config['id']}: 续期被拒绝（HTTP {response.status_code}），请重新登录",
                            CODE["credential"], status=response.status_code)
    if response.status_code >= 400:
        raise UpstreamError(f"{config['id']}: 续期失败（HTTP {response.status_code}）",
                            CODE["server"], status=response.status_code)
    payload = parse_token_payload(await _json_body(response))
    if not payload["accessToken"]:
        raise UpstreamError(f"{config['id']}: 续期响应缺少访问令牌", CODE["credential"])
    return apply_refresh(credential, payload)


# ── 模型目录 ───────────────────────────────────────────────────────────────

def fallback_catalog(product: dict | None = None) -> list[dict]:
    """内置兜底目录（``qoder-product.ts`` 的 ``QODER_FALLBACK_MODELS`` / ``…_CN_…``）。

    原版**从不**请求远端模型列表（该端点需要 WASM 签名），恒用本表 —— 本移植沿用。
    """
    config = _product(product)
    return [dict(model) for model in _models(config)]


def _decrypt_local_catalog(uid: str) -> Any | None:
    """尽力解密本机 ``~/.qoder/.models/<uid>/catalog-v6``（WASM ``model_cache_decrypt``）。

    仅用于**离线核对 / 补充**；失败（无文件、无 WASM、解密报错）一律返回 ``None``。
    """
    if not uid:
        return None
    path = Path(os.path.expanduser("~")) / ".qoder" / ".models" / str(uid) / MODEL_CACHE_FILE
    try:
        if not path.is_file():
            return None
        encrypted = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not encrypted:
        return None
    signer = _load_wasm()
    if signer is None:
        return None
    try:
        return json.loads(signer.decrypt_model_cache(encrypted, ""))
    except Exception:  # noqa: BLE001
        return None


def _models_from_catalog_json(data: Any) -> list[dict]:
    """从解密出的目录 JSON 里尽力提取模型条目（形状未逐一实测，故只做保守识别）。

    只认「带模型 key + 展示名」的对象；``key`` 字段名依次尝试
    ``key`` / ``id`` / ``model`` / ``model_key``。识别不出就返回空表。
    """
    found: list[dict] = []

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, list):
            for item in node:
                visit(item, depth + 1)
            return
        if not isinstance(node, dict):
            return
        model_id = read_string(node, ("key", "id", "model", "model_key"))
        display = read_string(node, ("display_name", "displayName", "name"))
        if model_id and display:
            found.append({"id": model_id, "name": display, "raw": node})
            return
        for value in node.values():
            visit(value, depth + 1)

    # 优先找 ``chat`` 场景（目录按场景分组）。
    if isinstance(data, dict):
        for key in ("chat", "models", "model_list", "chat_models"):
            if isinstance(data.get(key), (list, dict)):
                visit(data[key])
                if found:
                    break
    if not found:
        visit(data)
    return found


def _merge_catalog_models(local: list[dict], product: dict) -> list[dict]:
    """把解密出的本地条目并入兜底表：兜底表对**已知 id** 权威，本地表只补充新 id。"""
    index = {model["id"]: dict(model) for model in _models(product)}
    extra: list[dict] = []
    for item in local:
        model_id = item["id"]
        if model_id in index:
            continue
        extra.append({"id": model_id, "name": item["name"], "contextWindow": 200_000,
                      "vision": True, "reasoning": False})
    return list(index.values()) + extra


async def fetch_models(credential: dict, *, product: dict | None = None) -> dict:
    """返回 ``{"models":[{id,name,…}]}``；**任何失败都不抛错**，最差返回内置兜底表。

    数据来源（按优先级）：
    1. 兜底表（权威，逐条实测于 ``catalog-v6``）+ 本机目录缓存的**新增 id**（尽力）；
    2. 兜底表本身。

    注意 ``contextWindow`` 取目录**档位表的最大档**，不是 ``max_input_tokens``
    （两者经常自相矛盾，官方客户端只认档位表）。
    """
    config = _product(product)
    models = fallback_catalog(config)
    try:
        if isinstance(credential, dict) and credential.get("uid"):
            local = _models_from_catalog_json(_decrypt_local_catalog(str(credential["uid"])))
            if local:
                models = _merge_catalog_models(local, config)
    except Exception:  # noqa: BLE001
        models = fallback_catalog(config)
    for model in models:
        if model.get("contextWindow") is None:
            model["contextWindow"] = 200_000
        model.setdefault("vision", True)
        model.setdefault("reasoning", False)
        model.setdefault("maxOutput", DEFAULT_MAX_OUTPUT)
    return {"models": models, "at": int(time.time() * 1000)}


def display_name(model: dict) -> str:
    """模型展示名（原版会把倍率拼进 name；本移植只给纯名字，倍率留在字段里）。"""
    return str(model.get("name") or model.get("id") or "")


# ── WASM 签名（qoder-wasm.ts 的 wasm-bindgen 桥，纯 Python 重写） ──────────

#: WASM 文件的**搜索路径**（依次尝试）：
#: 1. 环境变量 ``OFM_QODER_WASM`` 指定的路径（部署时用）；
#: 2. 数据目录（``backend/data/``）；
#: 3. 源码树里的原版位置（开发机）。
def _wasm_candidates() -> list[Path]:
    here = Path(__file__).resolve()
    out: list[Path] = []
    explicit = (os.environ.get("OFM_QODER_WASM") or "").strip()
    if explicit:
        out.append(Path(explicit))
    # backend/data/（部署时把 wasm 放这里）
    out.append(here.parents[2] / "data" / "qoder-auth-wasm.wasm")
    # 源码树里的原版位置（开发机）：<repo>/old/dsh-our-free-model-main/vendor/channel-pack/src/
    out.append(here.parents[3] / "old" / "dsh-our-free-model-main" / "vendor"
               / "channel-pack" / "src" / "qoder-auth-wasm.wasm")
    # 原版编译产物旁的副本（lib/）。
    out.append(here.parents[3] / "old" / "dsh-our-free-model-main" / "vendor"
               / "channel-pack" / "qoder-auth-wasm.wasm")
    return out


#: wasm-bindgen 生成的 import 模块名（WASM 里 embed 了它，名字必须完全一致）。
IMPORT_MODULE = "./qoder_auth_wasm_bg.js"


def _signer_available() -> tuple[bool, str]:
    """返回 ``(是否可用, 详情)``：可用时详情是 wasm 路径，否则是原因说明。"""
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return False, ("未安装 wasmtime（`pip install wasmtime`）；"
                       "驱动该 WASM 需要它按 wasm-bindgen ABI 重建那层 JS glue")
    for path in _wasm_candidates():
        if path.is_file():
            return True, str(path)
    return False, ("找不到 qoder-auth-wasm.wasm；可用环境变量 OFM_QODER_WASM 指定其路径"
                   "（原版把它放在 vendor/channel-pack/src/ 与 lib/）")


class _WasmHeap:
    """wasm-bindgen 的「对象堆」+ 内存读写 + ABI 调用。

    ⚠️ 必须在实例化**之前**建好并交给 import 回调（回调里要用它），
    故它独立于 :class:`_QoderSigner`。
    """

    def __init__(self, store, exports) -> None:
        self.store = store
        self.exports = exports
        # 与官方 ``wW`` 一致：1024 个 undefined，再 push 四个哨兵。
        self.objects: list[Any] = [None] * 1024 + [None, None, True, False]
        self.first_free = len(self.objects)
        self.last_length = 0

    # ── 对象堆 ──
    def push(self, value):
        if self.first_free == len(self.objects):
            self.objects.append(len(self.objects) + 1)
        index = self.first_free
        self.first_free = self.objects[index]
        self.objects[index] = value
        return index

    def take(self, index):
        value = self.objects[index]
        if index >= 1028:
            self.objects[index] = self.first_free
            self.first_free = index
        return value

    def obj(self, index):
        return self.objects[index]

    # ── import 回调（名字与 wasm-bindgen 生成的 ``_bg.js`` 一一对应） ──
    def callbacks(self) -> dict:
        return {
            "__wbg_now_88621c9c9a4f3ffc": lambda: int(time.time() * 1000),
            "__wbg_new_with_length_9cedd08484b73942": lambda n: self.push({"data": bytearray(n)}),
            "__wbg_length_0c32cb8543c8e4c8": lambda a: len(self.obj(a)["data"]),
            "__wbg_subarray_0f98d3fb634508ad":
                lambda a, s, e: self.push({"data": bytearray(self.obj(a)["data"][s:e])}),
            "__wbg_prototypesetcall_3e05eb9545565046":
                lambda ptr, length, handle: (self.write(ptr, bytes(self.obj(handle)["data"][:length])), 0)[1],
            "__wbg_set_08463b1df38a7e29": self._set,
            "__wbindgen_object_drop_ref": lambda a: self.take(a),
            "__wbindgen_object_clone_ref": lambda a: self.push(self.obj(a)),
            "__wbindgen_cast_0000000000000001": lambda a, e: self.push(bytearray(self.read_bytes(a, e))),
            "__wbindgen_cast_0000000000000002": lambda a, e: self.push(self.read(a, e)),
            "__wbg___wbindgen_throw_81fc77679af83bc6": self._throw,
            "__wbg_Error_2e59b1b37a9a34c3": lambda p, l: self.push(self.read(p, l)),
            "__wbg___wbindgen_is_object_40c5a80572e8f9d3": lambda a: int(isinstance(self.obj(a), dict)),
            "__wbg___wbindgen_is_string_b29b5c5a8065ba1a": lambda a: int(isinstance(self.obj(a), str)),
            "__wbg___wbindgen_is_undefined_c0cca72b82b86f4d": lambda a: 0,
            "__wbg___wbindgen_is_function_49868bde5eb1e745": lambda a: 0,
            "__wbg_randomFillSync_6c25eac9869eb53c": lambda *a: 0,
            # ⚠️ 这两个签名方向**相反**：一个写 wasm 内存、一个调 JS 对象（坑 1）。
            "__wbg_getRandomValues_d49329ff89a07af1":
                lambda ptr, length: (self.write(ptr, os.urandom(length)), 0)[1],
            "__wbg_getRandomValues_c44a50d8cfdaebeb": self._get_random_object,
            "__wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f": lambda: self.push({}),
            "__wbg_static_accessor_GLOBAL_f2e0f995a21329ff": lambda: self.push({}),
            "__wbg_static_accessor_SELF_24f78b6d23f286ea": lambda: 0,
            "__wbg_static_accessor_WINDOW_59fd959c540fe405": lambda: 0,
            "__wbg_new_99cabae501c0a8a0": lambda: self.push({"kind": "map", "data": {}}),
            "__wbg_crypto_38df2bab126b63dc": lambda a: self.push({}),
            "__wbg_process_44c7a14e11e9f69e": lambda a: self.push({}),
            "__wbg_versions_276b2795b1c6a219": lambda a: self.push({}),
            "__wbg_node_84ea875411254db1": lambda a: self.push({}),
            "__wbg_msCrypto_bd5a034af96bcba6": lambda a: self.push({}),
            "__wbg_require_b4edbdcf3e2a1ef0": lambda *a: 0,
            "__wbg_call_d578befcc3145dee": lambda *a: 0,
        }

    def _set(self, target, source, offset):
        node = self.obj(target)
        if isinstance(node, dict) and node.get("kind") == "map":
            node["data"][str(self.obj(source))] = self.obj(offset)
            return 0
        data = node["data"]
        payload = self.obj(source)["data"]
        start = self.obj(offset)
        data[start:start + len(payload)] = payload
        return 0

    def _get_random_object(self, _handle, buffer_handle):
        data = self.obj(buffer_handle)["data"]
        data[:] = os.urandom(len(data))
        return 0

    def _throw(self, ptr, length):
        raise UpstreamError(f"qoder wasm threw: {self.read(ptr, length)}", CODE["server"])

    # ── 内存 ──
    def memory(self):
        return self.exports["memory"]

    def write(self, offset, raw: bytes) -> None:
        self.memory().write(self.store, raw, offset)

    def read_bytes(self, ptr, length) -> bytes:
        return self.memory().read(self.store, ptr, ptr + length)

    def read(self, ptr, length) -> str:
        return self.read_bytes(ptr, length).decode("utf-8", "replace")

    # ── ABI ──
    def write_string(self, text: str) -> int:
        encoded = text.encode("utf-8")
        ptr = self.exports["__wbindgen_export2"](self.store, len(encoded), 1) & 0xFFFFFFFF
        self.write(ptr, encoded)
        self.last_length = len(encoded)
        return ptr

    def int32(self, offset: int) -> int:
        import struct

        return struct.unpack("<i", self.read_bytes(offset, 4))[0]

    def call_string(self, invoke) -> str:
        """调用「字符串返回值」型函数（布局 ``ptr/len/valIdx/isErr``）。"""
        stack = self.exports["__wbindgen_add_to_stack_pointer"](self.store, -16)
        ptr = length = 0
        try:
            invoke(stack)
            ptr = self.int32(stack)
            length = self.int32(stack + 4)
            if self.int32(stack + 12):
                raise UpstreamError(f"qoder wasm error: {self.take(self.int32(stack + 8))!r}", CODE["server"])
            return self.read(ptr, length)
        finally:
            self.exports["__wbindgen_add_to_stack_pointer"](self.store, 16)
            if ptr:
                self.exports["__wbindgen_export4"](self.store, ptr, length, 1)

    def call_pointer(self, invoke) -> int:
        """调用「原始指针返回值」型函数（布局 ``ptr/errIdx/isErr`` —— 与上面**不同**，坑 2）。"""
        stack = self.exports["__wbindgen_add_to_stack_pointer"](self.store, -16)
        try:
            invoke(stack)
            if self.int32(stack + 8):
                raise UpstreamError(f"qoder wasm error: {self.take(self.int32(stack + 4))!r}", CODE["server"])
            return self.int32(stack)
        finally:
            self.exports["__wbindgen_add_to_stack_pointer"](self.store, 16)

    def result_string(self, result: int, name: str) -> str:
        """读 ``RequestResult`` 的字符串字段（``url`` / ``body``）。

        ⚠️ 参数顺序 ``(栈指针, ptr)`` —— 与直觉相反（坑 3）。
        """
        stack = self.exports["__wbindgen_add_to_stack_pointer"](self.store, -16)
        try:
            self.exports[f"requestresult_{name}"](self.store, stack, result)
            ptr = self.int32(stack)
            length = self.int32(stack + 4)
            return self.read(ptr, length) if ptr else ""
        finally:
            self.exports["__wbindgen_add_to_stack_pointer"](self.store, 16)


class _QoderSigner:
    """用 Python 直接驱动 ``qoder-auth-wasm.wasm``（原版 ``qoder-wasm.ts`` 的等价重写）。

    重建了 wasm-bindgen 那层 glue：对象堆、字符串进出、
    ``__wbindgen_add_to_stack_pointer``、两套返回值布局，以及两个方向相反的
    ``getRandomValues`` import。

    **不做任何解密/破解**：WASM 自己导出了成对的编解码函数，这里只是调用它
    —— 等同「用客户端自己的钥匙开自己的锁」。
    """

    def __init__(self, store, heap: _WasmHeap, exports) -> None:
        self.store = store
        self.heap = heap
        self.exports = exports

    @classmethod
    def load(cls, path: Path) -> "_QoderSigner":
        import wasmtime

        engine = wasmtime.Engine()
        module = wasmtime.Module.from_file(engine, str(path))
        store = wasmtime.Store(engine)

        def placeholder(*_args):
            return 0

        # ⚠️ ``memory`` 等导出要在**实例化之后**才拿得到，而 import 回调在实例化**期间**
        # 就会被调用 —— 故先建一个空 dict 交给 :class:`_WasmHeap`，实例化后原地填充
        # （heap 与 signer 共享同一个 dict 对象，填充即生效）。
        exports: dict[str, Any] = {}
        heap = _WasmHeap(store, exports)
        callbacks = heap.callbacks()

        linker = wasmtime.Linker(engine)
        for import_ in module.imports:
            handler = callbacks.get(import_.name, placeholder)
            results = import_.type.results

            def make(fn, types):
                if not types:
                    def wrapped(*args):
                        fn(*args)
                        return None
                    return wrapped
                wants_float = "f64" in str(types[0])

                def wrapped_value(*args):
                    value = fn(*args)
                    return float(value) if wants_float else int(value)
                return wrapped_value

            linker.define(store, import_.module, import_.name,
                          wasmtime.Func(store, import_.type, make(handler, results)))

        instance = linker.instantiate(store, module)
        exports.update(instance.exports(store))
        return cls(store, heap, exports)

    # ── 对外：与 qoder-wasm.ts 导出的函数一一对应 ──

    def generate_runtime_auth_fields(self, user: dict) -> dict:
        """``generate_runtime_auth_fields`` → ``{encrypt_user_info, key}``。"""
        payload = json.dumps({
            "uid": user.get("uid") or "",
            "security_oauth_token": user.get("securityOauthToken") or "",
            "organization_id": user.get("organizationId") or "",
            "organization_tags": list(user.get("organizationTags") or []),
            "data_policy_agreed": bool(user.get("dataPolicyAgreed")),
        }, ensure_ascii=False)

        def invoke(stack):
            ptr = self.heap.write_string(payload)
            self.exports["generate_runtime_auth_fields"](self.store, stack, ptr, self.heap.last_length)

        return json.loads(self.heap.call_string(invoke))

    def decrypt_model_cache(self, encrypted: str, machine_id: str) -> str:
        """``model_cache_decrypt(密文, machineId)``。

        ⚠️ ``machine_id`` 是**必填的第二参**；漏传会得到
        ``AES-GCM decrypt failed: aead::Error``（看着像密文损坏，其实是缺参数）。
        """

        def invoke(stack):
            first = self.heap.write_string(encrypted)
            first_len = self.heap.last_length
            second = self.heap.write_string(machine_id)
            self.exports["model_cache_decrypt"](self.store, stack, first, first_len,
                                                second, self.heap.last_length)

        return self.heap.call_string(invoke)

    def prepare_infer(self, *, user: dict, machine_id: str, client_version: str, metadata: dict,
                      host: str, payload: dict, model_key: str, source: str) -> dict:
        """构造一次加密推理请求，返回 ``{url, headers, body}``。

        ``headers`` 里的 ``Authorization`` 是 WASM 生成的
        ``Bearer COSY.<载荷>.<签名>``，**必须原样透传**（覆盖成普通 Bearer 会
        403 ``Signature invalid``）。
        """
        fields = self.generate_runtime_auth_fields(user)
        user_info = json.dumps({
            "uid": user.get("uid") or "",
            "encrypt_user_info": fields["encrypt_user_info"],
            "key": fields["key"],
            "organization_id": user.get("organizationId") or "",
            "organization_tags": list(user.get("organizationTags") or []),
            "data_policy_agreed": bool(user.get("dataPolicyAgreed")),
        }, ensure_ascii=False)

        def new_context(stack):
            machine = self.heap.write_string(machine_id)
            machine_len = self.heap.last_length
            version = self.heap.write_string(client_version)
            version_len = self.heap.last_length
            info = self.heap.write_string(user_info)
            info_len = self.heap.last_length
            meta = self.heap.write_string(json.dumps(metadata, ensure_ascii=False))
            meta_len = self.heap.last_length
            # 参数顺序：(sp, machineId, len, version, len, userInfo, len, clientMeta, len)
            self.exports["qodercontext_new"](self.store, stack, machine, machine_len, version, version_len,
                                             info, info_len, meta, meta_len)

        context = self.heap.call_pointer(new_context)
        body_text = json.dumps(payload, ensure_ascii=False)

        def prepare(stack):
            host_ptr = self.heap.write_string(host)
            host_len = self.heap.last_length
            body_ptr = self.heap.write_string(body_text)
            body_len = self.heap.last_length
            key_ptr = self.heap.write_string(model_key)
            key_len = self.heap.last_length
            source_ptr = self.heap.write_string(source)
            source_len = self.heap.last_length
            self.exports["qodercontext_prepareInferRequest"](
                self.store, stack, context, host_ptr, host_len, body_ptr, body_len,
                key_ptr, key_len, source_ptr, source_len)

        result = self.heap.call_pointer(prepare)
        raw = self.heap.take(self.exports["requestresult_headers"](self.store, result))
        if isinstance(raw, dict) and raw.get("kind") == "map":
            raw = raw["data"]
        headers = {str(key): str(value) for key, value in (raw or {}).items()}
        return {
            "url": self.heap.result_string(result, "url"),
            "headers": headers,
            "body": self.heap.result_string(result, "body"),
        }


#: 进程级单例（WASM 实例无状态，可复用；一个账号一个 context 即可）。
_SIGNER: "_QoderSigner | None" = None
_SIGNER_ERROR: "str | None" = None


def _load_wasm() -> "_QoderSigner | None":
    """建立（或复用）WASM 驱动；不可用时返回 ``None``（原因记在 :data:`_SIGNER_ERROR`）。"""
    global _SIGNER, _SIGNER_ERROR
    if _SIGNER is not None:
        return _SIGNER
    available, detail = _signer_available()
    if not available:
        _SIGNER_ERROR = detail
        return None
    try:
        _SIGNER = _QoderSigner.load(Path(detail))
    except Exception as error:  # noqa: BLE001
        _SIGNER_ERROR = f"加载 {detail} 失败：{error.__class__.__name__}: {error}"
        return None
    return _SIGNER


def signer_status() -> dict:
    """诊断用：WASM 驱动是否可用、原因、以及端点/静态参数。"""
    signer = _load_wasm()
    available, detail = _signer_available()
    return {
        "available": signer is not None,
        "detail": detail if signer is not None else (_SIGNER_ERROR or detail),
        "sessionType": SESSION_TYPE,
        "cosyVersion": COSY_VERSION,
        "endpoint": ENCRYPTED_CHAT_PATH,
        "query": dict(ENCRYPTED_CHAT_QUERY),
    }


# ── 推理请求体（qoder-wasm.ts 的 buildQoderInferPayload / qoder-adapter.ts） ──

def _content_text(content: Any) -> str:
    """把 content 归一化为文本（工具调用消息的正文是空串）。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(block.get("text") or "") for block in content
                       if isinstance(block, dict) and block.get("type") == "text")
    return ""


def _content_parts(content: Any) -> list[dict] | None:
    """把 content 数组逐字段搬运成多模态 parts；**无图时返回 ``None``**。

    ⚠️ 图片走 **``messages[].content`` 的多模态数组**，**不走** ``chat_context.imageUrls``
    （官方 ``Hyc()`` 把那个字段恒置 ``null``）。把 content 压成纯文本会让图片全部消失。
    """
    if not isinstance(content, list):
        return None
    parts: list[dict] = []
    has_image = False
    for raw in content:
        if not isinstance(raw, dict):
            continue
        kind = raw.get("type")
        if kind == "text":
            text = str(raw.get("text") or "")
            if text:
                parts.append({"type": "text", "text": text})
            continue
        if kind in ("image_url", "image"):
            block = raw.get("image_url") if kind == "image_url" else raw.get("source")
            url = block.get("url") if isinstance(block, dict) else None
            if isinstance(url, str) and url:
                detail = block.get("detail") if isinstance(block, dict) else None
                entry: dict[str, Any] = {"type": "image_url", "image_url": {"url": url}}
                if isinstance(detail, str) and detail:
                    entry["image_url"]["detail"] = detail
                parts.append(entry)
                has_image = True
    return parts if has_image else None


def build_history(messages: Any) -> list[dict]:
    """把 OpenAI 形状消息转成加密端点的 ``messages[]``。

    ⚠️ 必须保留 assistant 的 ``tool_calls``（其 ``content`` 常为 ``null``）与
    ``role:'tool'`` 的 ``tool_call_id``：丢掉它们模型就看不到自己调用过什么，
    表现为反复重调同一工具或凭空编造结果。
    """
    history: list[dict] = []
    if not isinstance(messages, list):
        return history
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if not isinstance(role, str) or role == "":
            continue
        parts = _content_parts(message.get("content"))
        content: Any = parts if parts is not None else _content_text(message.get("content"))
        tool_calls = message.get("tool_calls")
        tool_calls = tool_calls if isinstance(tool_calls, list) and tool_calls else None
        call_id = message.get("tool_call_id")
        call_id = call_id if isinstance(call_id, str) and call_id else None
        empty = (len(content) == 0) if isinstance(content, (str, list)) else True
        if empty and tool_calls is None and call_id is None:
            continue
        entry: dict[str, Any] = {"role": role, "content": content}
        if tool_calls is not None:
            entry["tool_calls"] = tool_calls
        if call_id is not None:
            entry["tool_call_id"] = call_id
        history.append(entry)
    return history


def build_tools(tools: Any) -> list[dict]:
    """把工具定义转成加密端点顶层 ``tools``（客户端 ``$Hc(A)`` 的形态）。

    ⚠️ **必须真的下发**：不下发时模型拿不到任何函数 schema，只能用正文里的 XML 文本
    臆造工具调用（原版记录过「任务调用 xml 泄露」的真实缺陷）。省略等价于空数组。
    """
    if not isinstance(tools, list) or not tools:
        return []
    out: list[dict] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = function.get("name")
        if not isinstance(name, str) or name == "":
            continue
        entry: dict[str, Any] = {"type": "function", "function": {"name": name}}
        description = function.get("description")
        if isinstance(description, str) and description:
            entry["function"]["description"] = description
        parameters = function.get("parameters")
        if isinstance(parameters, dict):
            entry["function"]["parameters"] = parameters
        out.append(entry)
    return out


def normalize_effort(value: Any, model: dict) -> str | None:
    """把请求里的 ``reasoning_effort`` 归一化到白名单内；不在表里返回 ``None``。"""
    if not isinstance(value, str) or value == "":
        return None
    effort = EFFORT_ALIASES.get(value.strip().lower(), value.strip().lower())
    return effort if effort in EFFORT_WHITELIST else None


def build_infer_payload(body: dict, model_id: str, model: dict, *, request_id: str | None = None) -> dict:
    """构造加密端点 ``agent_chat_generation`` 的**明文**请求体（官方 ``G4A()`` 的结构）。

    ⚠️ 两条硬约束（原版实测）：
    - ``chat_context`` 不能传空对象；
    - **``business`` 必填** —— 缺了服务端会把请求路由到故障节点（``qfmodel`` 因此被
      误判为「服务端故障」，而 IDE 里同一模型完全正常）。
    """
    rid = request_id or str(uuid.uuid4())
    # ⚠️ system 消息**保留在 ``messages[]`` 里**（原版 ``buildQoderHistory`` 就是逐条搬运，
    # 并没有把 system 提出来）——把顶层 ``system`` 当成唯一通道会与上游形态不符。
    messages = build_history(body.get("messages"))
    user_text = ""
    for message in reversed(messages):
        if message.get("role") == "user":
            user_text = _content_text(message.get("content")) or ""
            break
    if not messages:
        messages = [{"role": "user", "content": user_text}]

    # 顶层 ``system``：官方形态是 ``[{type:'text', text}]``，无系统提示时是**空数组**（键恒在）。
    # 取值口径与原版一致：来自适配器单独拿到的那份 system 提示（本移植对应 ``body["system"]``）。
    system_value = body.get("system")
    if isinstance(system_value, str):
        system_text = system_value
    elif isinstance(system_value, list):
        system_text = "\n\n".join(
            str(part.get("text") or "") for part in system_value
            if isinstance(part, dict) and part.get("type") in ("text", "input_text"))
    else:
        system_text = ""

    reasoning = bool(model.get("reasoning"))
    effort = normalize_effort(body.get("reasoning_effort"), model)
    if effort is None and model.get("reasoningEfforts"):
        effort = model.get("defaultReasoningEffort") or None
    if effort == "none":
        reasoning = False

    parameters: dict[str, Any] = {}
    max_tokens = body.get("max_tokens")
    if isinstance(max_tokens, int) and not isinstance(max_tokens, bool) and max_tokens > 0:
        parameters["max_tokens"] = max_tokens
    if effort is not None:
        parameters["reasoning_effort"] = effort
        parameters["enable_thinking"] = effort != "none"
    context_window = model.get("contextWindow")
    if isinstance(context_window, int) and context_window > 0:
        parameters["context_length"] = context_window

    return {
        "request_id": rid,
        "request_set_id": rid,
        "chat_record_id": rid,
        "session_id": str(uuid.uuid4()),
        "stream": True,
        "chat_task": "FREE_INPUT",
        "chat_context": {
            "text": user_text,
            "features": [],
            "extra": {"context": [], "modelConfig": {"key": model_id, "is_reasoning": reasoning},
                      "originalContent": user_text},
            "chatPrompt": "",
            "imageUrls": None,
        },
        "is_reply": True,
        "is_retry": False,
        "source": 1,
        "version": "3",
        "agent_id": "agent_common",
        "task_id": "common",
        "session_type": SESSION_TYPE,
        "aliyun_user_type": "",
        "model_config": {
            "key": model_id,
            "display_name": model.get("name") or "",
            "model": "",
            "format": "openai",
            "is_vl": bool(model.get("vision")),
            "is_reasoning": reasoning,
            "api_key": "",
            "url": "",
            "source": "system",
            "max_input_tokens": context_window if isinstance(context_window, int) else 200_000,
        },
        "custom_model": None,
        "system": [{"type": "text", "text": system_text}] if system_text else [],
        "messages": messages,
        "tools": build_tools(body.get("tools")),
        "parameters": parameters,
        "business": dict(BUSINESS),
    }


# ── 响应信封（qoder-envelope.ts） ──────────────────────────────────────────

def unwrap_envelope(payload: str) -> str | None:
    """剥掉 ``{"body": "<标准 OpenAI 帧>"}`` 信封；不是信封时返回 ``None``。

    ⚠️ 内层 ``body`` **未加密** —— 只有**请求**体需要 WASM 加密。
    """
    try:
        envelope = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(envelope, dict) or "body" not in envelope:
        return None
    body = envelope["body"]
    if isinstance(body, str):
        return body
    return json.dumps(body, ensure_ascii=False)


def classify_inner(inner: str) -> str:
    """给内层帧分类：``chunk`` / ``error`` / ``heartbeat``（按 JSON 结构，不靠子串嗅探）。"""
    text = inner.strip()
    if text == "":
        return "heartbeat"
    if "[DONE]" in text:
        return "chunk"
    try:
        parsed = json.loads(text)
    except ValueError:
        return "error"
    if parsed is None or not isinstance(parsed, dict):
        return "heartbeat"
    if isinstance(parsed.get("choices"), list) or parsed.get("usage") is not None:
        return "chunk"
    if any(parsed.get(key) is not None for key in ("code", "message", "error", "statusCodeValue", "type")):
        return "error"
    return "heartbeat"


_BUSINESS_CODE = re.compile(r'"?code"?\s*[:=]\s*"?(\d+)"?')
_RETRY_AFTER = re.compile(r"retryAfterSeconds\s*[:=]\s*\"?(\d+)")


def business_code(text: str) -> str:
    match = _BUSINESS_CODE.search(text or "")
    return match.group(1) if match else ""


def retry_after_seconds(text: str) -> int | None:
    match = _RETRY_AFTER.search(text or "")
    return int(match.group(1)) if match else None


def _error_code(status: int) -> str:
    if status in (401, 403):
        return CODE["credential"]
    if status == 429:
        return CODE["quota"]
    if status >= 500:
        return CODE["server"]
    return CODE["client"]


# ── 推理（qoder-adapter.ts 的 stream） ────────────────────────────────────

async def _ensure_uid(credential: dict, product: dict, on_refresh: Callable[[dict], None] | None) -> dict:
    """确保凭据带 ``uid``（加密推理必需），必要时调一次 userinfo 并回写。

    ⚠️ 缺 uid 时**不能静默用空串发请求** —— WASM 会产出签名无效的请求，
    服务端回 ``Signature invalid (101)``，用户看到的是「签名错误」而非「凭据不完整」。
    """
    if isinstance(credential.get("uid"), str) and credential["uid"]:
        return credential
    info = await fetch_userinfo(credential, product)
    if info is None:
        return credential
    uid = read_string(info, ("id", "uid", "user_id"))
    if not uid:
        return credential
    patched = dict(credential)
    patched["uid"] = uid
    name = info.get("name")
    if isinstance(name, str) and name.strip():
        patched["nickname"] = name.strip()
    if on_refresh is not None:
        on_refresh(patched)
    return patched


async def _send(request: dict, timeout_s: float) -> httpx.Response:
    """发送一次加密推理请求（``headers`` **原样透传**）。"""
    client = await get_client()
    return await client.send(
        client.build_request("POST", request["url"], headers=request["headers"], content=request["body"]),
        stream=True)


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None,
                 product: dict | None = None) -> AsyncIterator[dict]:
    """走客户端真实链路（加密端点）跑一轮推理，以内部 chunk 产出。

    ``catalog`` 由管理器传入（``fetch_models`` 的结果），用于补齐模型元信息。

    **降级说明**：本端点要求 ``Authorization: Bearer COSY.<载荷>.<签名>``，该签名由
    ``qoder-auth-wasm.wasm`` 生成，**无法用纯 Python 复刻**（理由见模块 docstring）。
    驱动方式有两选一：

    - 装 ``wasmtime``（``pip install wasmtime``）并让 wasm 文件可被找到
      （``OFM_QODER_WASM`` 或 ``backend/data/``）；
    - 否则抛 :class:`NotImplementedError`，**不编造签名、不回退到公开端点**
      （公开端点只认通用名 ``qwen-flash`` 之类，拿目录 key 请求会
      ``Unsupported model``，静默降级只会掩盖问题）。
    """
    config = _product(product)
    channel_id = config["id"]
    model_id = str(body.get("model") or "")
    if model_id == "":
        raise UpstreamError(f"{channel_id}: 请求缺少 model", CODE["client"])

    known = _index(config)
    entry = dict(known.get(model_id) or {"id": model_id, "name": model_id})
    if isinstance(catalog, dict):
        for model in catalog.get("models") or []:
            if isinstance(model, dict) and model.get("id") == model_id:
                entry = {**entry, **{k: v for k, v in model.items() if v is not None}}
                break

    signer = _load_wasm()
    if signer is None:
        raise NotImplementedError(
            f"{channel_id}: 无法生成加密推理所需的签名 —— {_SIGNER_ERROR or _signer_available()[1]}。"
            "Qoder 的 Authorization 头是 `Bearer COSY.<载荷>.<签名>`，由 qoder-auth-wasm.wasm "
            f"（wasm-bindgen 产物）生成，签名在 WASM 内部，实测无法用纯 Python 复刻（md5/hmac 各变体均不匹配）。"
            "该端点认模型目录 key（qfmodel 等），公开的 OpenAI 兼容端点不认它们，故不做降级。"
            "安装 wasmtime 并按 OFM_QODER_WASM 指定 wasm 路径即可启用。")

    credential = await _ensure_uid(dict(credential), config, on_refresh)
    uid = credential.get("uid") or ""
    if uid == "":
        raise UpstreamError(f"{channel_id}: 凭据缺少 uid，加密推理无法签名（请重新登录该账号）",
                            CODE["credential"])

    payload = build_infer_payload(body, model_id, entry)
    request = signer.prepare_infer(
        user={"uid": str(uid), "securityOauthToken": bearer_token(credential)},
        machine_id=str(credential.get("machine_id") or ""),
        client_version=COSY_VERSION,
        metadata=dict(config["clientMetadata"]),
        host=config["encryptedInferBase"],
        payload=payload,
        model_key=model_id,
        source="system",
    )

    channel = create_channel()
    auth_refreshed = False
    queue_waited = False

    def forward(payload_text: str) -> None:
        """剥信封 → 心跳丢弃 → 排队/错误帧如实报错 → 正常帧送进内部流。"""
        inner = unwrap_envelope(payload_text)
        if inner is None:
            channel.push(payload_text)
            return
        kind = classify_inner(inner)
        if kind == "heartbeat":
            return
        if kind == "error":
            code = business_code(inner)
            if code in ("10605", "110"):
                wait = retry_after_seconds(inner)
                raise UpstreamError(
                    f"{channel_id}: 服务端排队/额度受限（业务码 {code}）"
                    + (f"，要求等待 {wait} 秒" if wait is not None else "")
                    + "；这是 HTTP 200 流内错误帧，未产出任何内容，可稍后重试整轮请求",
                    CODE["quota"])
            message = inner
            try:
                parsed = json.loads(inner)
                if isinstance(parsed.get("message"), str):
                    message = parsed["message"]
            except ValueError:
                pass
            raise UpstreamError(f"{channel_id}: {message[:300]}", _error_code(0))
        channel.push(inner)

    async def produce() -> None:
        nonlocal credential, auth_refreshed, queue_waited, request
        try:
            for attempt in range(4):
                response = await _send(request, STREAM_TIMEOUT_S)
                if response.status_code in (401, 403, 409) and attempt < 3:
                    text = (await response.aread()).decode("utf-8", "replace")
                    await response.aclose()
                    code = business_code(text)
                    if code in ("10605", "110"):
                        # 排队：按服务端给的延迟等待后重发（未产出任何 chunk，可安全重放）。
                        if queue_waited:
                            raise UpstreamError(f"{channel_id}: 服务端持续排队：{text[:200]}",
                                                CODE["quota"], status=response.status_code)
                        queue_waited = True
                        wait = retry_after_seconds(text) or 30
                        await asyncio.sleep(min(wait, 120))
                        continue
                    if response.status_code == 409:
                        # 重复请求：凭据没问题，重发一次即可。
                        continue
                    if not auth_refreshed:
                        # 认证失败：**唯一**该走续期的情形，每次请求最多一次。
                        auth_refreshed = True
                        refreshed = await refresh_credential(credential, product=config)
                        credential = await _ensure_uid(refreshed, config, on_refresh)
                        if on_refresh is not None:
                            on_refresh(credential)
                        request = signer.prepare_infer(
                            user={"uid": str(credential.get("uid") or ""),
                                  "securityOauthToken": bearer_token(credential)},
                            machine_id=str(credential.get("machine_id") or ""),
                            client_version=COSY_VERSION,
                            metadata=dict(config["clientMetadata"]),
                            host=config["encryptedInferBase"],
                            payload=payload, model_key=model_id, source="system")
                        continue
                    raise UpstreamError(f"{channel_id}: {text[:300]}", CODE["credential"],
                                        status=response.status_code)
                if response.status_code >= 400:
                    text = (await response.aread()).decode("utf-8", "replace")
                    await response.aclose()
                    raise UpstreamError(f"{channel_id}: HTTP {response.status_code} {text[:300]}",
                                        _error_code(response.status_code), status=response.status_code)
                head = await read_head(response.aiter_bytes(), 4096, STREAM_TIMEOUT_S)
                shape = sniff_body(head.text)
                if shape == "empty":
                    raise UpstreamError(f"{channel_id}: 上游返回空响应体", CODE["empty"])
                if shape == "sse":
                    await read_sse(_replay(head), forward, STREAM_TIMEOUT_S)
                else:
                    text = (await _read_remainder(head)).decode("utf-8", "replace")
                    inner = unwrap_envelope(text)
                    if inner is None:
                        raise UpstreamError(f"{channel_id}: 非流式且非信封的响应：{text[:200]}", CODE["server"])
                    if classify_inner(inner) == "error":
                        raise UpstreamError(f"{channel_id}: {inner[:300]}", _error_code(0))
                    channel.push(inner)
                channel.push(None)
                return
            raise UpstreamError(f"{channel_id}: 排队重试次数已用尽", CODE["quota"])
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
