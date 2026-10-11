"""Kilo 渠道的出站线格式。

Kilo AI 提供 OpenAI 兼容网关，其免费池无需任何凭据（无 key、无登录、无指纹闸门）。
代价写在网关自己的模型卡上：免费池的提示词可能被上游记录并用于改进服务。
"""

from __future__ import annotations

import json
import os
from typing import Callable

import httpx

from .http_client import (
    CODE,
    UpstreamError,
    classify_failure,
    get_client,
    read_head,
    read_sse,
    _read_remainder,
    _replay,
    sniff_body,
)

LISTING_TIMEOUT_MS = 15000
TURN_TIMEOUT_MS = 300000

KILO_BASE = os.environ.get("OUR_FREE_MODEL_KILO_BASE", "https://api.kilo.ai/api/gateway").rstrip("/")


async def fetch_kilo_listing(timeout_ms: int = LISTING_TIMEOUT_MS):
    """拉取一次清单：``GET {base}/models``。"""
    client = await get_client()
    try:
        response = await client.get(f"{KILO_BASE}/models",
                                    headers={"accept": "application/json", "user-agent": "dsh-our-free-model"},
                                    timeout=timeout_ms / 1000.0)
        text = response.text
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {"error": {"message": text[:300] or f"HTTP {response.status_code}"}}
        if response.status_code >= 400:
            raise classify_failure(response.status_code, payload)
        return payload
    except UpstreamError:
        raise
    except httpx.TimeoutException:
        raise UpstreamError("model listing timed out", CODE["timeout"])
    except httpx.HTTPError as error:
        raise UpstreamError(f"model listing failed: {error}", CODE["transport"])


def _classify_kilo(status: int, text: str, retry_after_ms: int | None = None) -> UpstreamError:
    try:
        payload = json.loads(text)
    except ValueError:
        payload = {"error": {"message": text[:300] or f"HTTP {status}"}}
    error = payload.get("error") if isinstance(payload, dict) else {}
    error = error if isinstance(error, dict) else {}
    etype = payload.get("error_type") if isinstance(payload, dict) else None
    etype = etype or error.get("code") or error.get("type")
    shaped = {"error": {**error, **({} if etype is None else {"type": str(etype)})}}
    if isinstance(etype, str) and "PAID_MODEL_AUTH_REQUIRED" in etype.upper():
        return UpstreamError("this model is not on the free pool: it needs a Kilo account, so it is not served by this channel",
                             CODE["client"], status=status)
    failure = classify_failure(status, shaped, retry_after_ms)
    if isinstance(failure.message, str) and any(w in failure.message.lower() for w in ("moderation", "flagged", "filtered")):
        return UpstreamError(failure.message, CODE["client"], status=status)
    return failure


async def post_kilo_streamed(body: dict, on_data: Callable[[str], None], timeout_ms: int = TURN_TIMEOUT_MS) -> None:
    """POST 一轮并流式回传解码后的 SSE ``data:`` 负载。"""
    client = await get_client()
    timeout_s = max(1.0, timeout_ms / 1000.0)
    try:
        async with client.stream(
            "POST", f"{KILO_BASE}/chat/completions",
            headers={"content-type": "application/json", "accept": "text/event-stream", "user-agent": "dsh-our-free-model"},
            content=json.dumps(body),
            timeout=httpx.Timeout(connect=15.0, read=timeout_s, write=60.0, pool=15.0),
        ) as response:
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                raise _classify_kilo(response.status_code, text)
            head = await read_head(response.aiter_bytes(), 4096, timeout_s)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("model stream returned no body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), on_data, timeout_s)
                return
            text = (await _read_remainder(head)).decode("utf-8", "replace")
            try:
                payload = json.loads(text)
            except ValueError:
                raise UpstreamError(f"unexpected non-stream response: {text[:200]}", CODE["server"], status=response.status_code)
            if isinstance(payload, dict) and payload.get("error"):
                raise _classify_kilo(response.status_code, text)
            on_data(json.dumps(payload))
    except UpstreamError:
        raise
    except httpx.TimeoutException as error:
        raise UpstreamError(f"model request timed out: {error}", CODE["timeout"])
    except httpx.HTTPError as error:
        raise UpstreamError(f"model request failed: {error}", CODE["transport"])
