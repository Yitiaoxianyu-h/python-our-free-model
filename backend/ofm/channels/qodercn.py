"""Qoder **中国版**（``qodercn``）渠道。

中国版与国际版**共用同一套协议实现**（原版把差异全部收敛进一份产品配置：
``qoder-product.ts`` 的 ``QODER_CN``），故本模块**不复制任何实现**，
只 import :mod:`ofm.channels.qoder` 并把产品配置换成 ``PRODUCT_CN``。
与原版 ``qoder-adapter.ts`` / ``qoder-auth.ts`` 的 ``product`` 注入同一思路。

## 与国际版的差异（``qoder-product.ts``）

| 项 | qoder（国际版） | qodercn（中国版） |
|---|---|---|
| provider id / ``Cosy-*`` | ``qoder`` | ``qodercn`` |
| 登录与 OAuth 基址 | ``https://qoder.com`` | ``https://qoder.cn`` |
| OpenAPI 基址（轮询 / 续期 / userinfo） | ``https://openapi.qoder.sh`` | ``https://openapi.qoder.com.cn`` |
| 加密推理 host | ``https://api2.qoder.sh`` | ``https://gateway.qoder.com.cn`` |
| 公开 OpenAI 兼容端点 | ``https://api2-v2.qoder.sh`` | **没有可用的**（实测回 503） |
| OAuth ``client_id``（prod） | ``e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb`` | ``732aef47-9cf2-46a2-95fe-4cebb5d0d1fa`` |
| 凭据 ref | ``QODER_ACCESS_TOKEN`` | ``QODERCN_ACCESS_TOKEN`` |
| 模型表 | 17 条 | 14 条（含 CN 独有 ``q37fmodel`` / ``gm51model``；``mmodel`` 是 M2.7 且窗口 200K） |

⚠️ CN 的 ``client_id`` 与国际版**完全不同**（国际版两个 id 在 CN asar 里命中 0 次）。
用错的症状是「授权页 302 正常、点击授权后报参数无效」，故不能靠探测入口验证。

## 登录 / 续期 / 目录 / 推理

- **登录**：PKCE 设备码轮询（不起本地服务器），见 :func:`qoder.run_login`；
- **续期**：``POST /api/v1/deviceToken/refresh``，体为 ``{refresh_token, machine_id}``；
- **目录**：兜底表（逐条实测 ``catalog-v6``）+ 本机缓存里出现的新 id，**失败不抛错**；
- **推理**：加密端点 ``/algo/api/v2/service/pro/sse/agent_chat_generation``，
  ``Authorization`` 由 ``qoder-auth-wasm.wasm`` 生成。CN 与国际版**共用同一个 wasm 与
  同一个 ``Cosy-Version``（1.1.49）**，差异只在 host 与 client_id —— 均已由配置区分。

**WASM 能否在 Python 复刻**：能驱动（用 ``wasmtime`` 重建 wasm-bindgen 的 JS glue），
但**签名本身无法脱离 WASM 用纯 Python 复刻**（实测 md5/hmac 各变体均不匹配）。
详见 :mod:`ofm.channels.qoder` 的模块 docstring；未装 ``wasmtime`` 且 wasm 不可见时，
:func:`stream` 会抛 ``NotImplementedError`` 并说明原因，**不编造签名、不静默降级到公开端点**。
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable

# 同属一家产品，实现完全复用（这是原版「一份实现 + 两份配置」的直接对应）。
from . import qoder as _qoder
from .qoder import (  # noqa: F401  （重新导出便于调用方直接引用）
    CONTEXT_WINDOWS_CN,
    FALLBACK_INDEX_CN,
    FALLBACK_MODELS_CN,
    LOGIN_TIMEOUT_S,
    POLL_INTERVAL_S,
    PRODUCT_CN,
    display_name,
    fallback_catalog,
    fetch_userinfo,
    is_expired,
    is_refreshable,
    parse_token_payload,
    signer_status,
)

CHANNEL_ID = "qodercn"

#: 本渠道的产品配置（中国版）。
PRODUCT: dict[str, Any] = PRODUCT_CN

#: 兜底模型目录的 id → 上下文窗口（管理器按它补 ``contextWindow``）。
CONTEXT_WINDOWS: dict[str, int] = dict(CONTEXT_WINDOWS_CN)


async def run_login(*, open_browser: bool = True, timeout_s: float = LOGIN_TIMEOUT_S,
                    poll_interval_s: float = POLL_INTERVAL_S,
                    print_fn: Callable[[str], None] = print) -> dict:
    """跑一次中国版登录（PKCE 设备码轮询），返回凭据 dict。"""
    return await _qoder.run_login(open_browser=open_browser, timeout_s=timeout_s,
                                  poll_interval_s=poll_interval_s, product=PRODUCT,
                                  print_fn=print_fn)


async def refresh_credential(credential: dict) -> dict:
    """用 ``refresh_token`` + ``machine_id`` 静默续期（挂 CN 的 ``openApiBase``）。"""
    return await _qoder.refresh_credential(credential, product=PRODUCT)


async def fetch_models(credential: dict) -> dict:
    """返回 ``{"models":[{id,name,…}]}``；**任何失败都不抛错**，最差给 CN 兜底表。"""
    return await _qoder.fetch_models(credential, product=PRODUCT)


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """走 CN 的加密端点跑一轮推理，以内部 chunk 产出。

    依赖 ``qoder-auth-wasm.wasm`` 生成 ``Bearer COSY.<载荷>.<签名>``；
    驱动不了时抛 ``NotImplementedError``（原因见模块 docstring 与
    :func:`qoder.signer_status`），**不编造签名**。
    """
    async for chunk in _qoder.stream(body, credential, catalog=catalog, on_refresh=on_refresh,
                                     product=PRODUCT):
        yield chunk
