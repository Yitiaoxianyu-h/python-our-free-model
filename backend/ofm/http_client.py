"""免费车道的出站 HTTP：请求投递、SSE 行提取、失败分类。

网关把拒绝表示为 ``type`` 字段为机器可读判别式的 JSON 错误信封。
三种需要区别处理：RegionError（出口地区被排除）、
FreeUsageLimitError/429（按会话的额度耗尽）、ModelError（该 id 不再被路由）。

2xx 响应体如何读取由**响应体形状**决定，不由 ``Content-Type`` 决定：
该网关被观测到以 JSON 的 content-type 返回完整的 SSE 帧序列（issue #6）。
先嗅探头部若干字节再回灌进流读取器，不缓冲任何 token。
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable

import httpx

from .upstream import CLIENT_UA, UPSTREAM_BASE, gateway_headers, truncate_session

# 与 harness 无关的失败码。
CODE = {
    "region": "REGION_BLOCKED",
    "quota": "RATE_LIMIT",
    "credential": "INVALID_CREDENTIAL",
    "authorization": "AUTHORIZATION_REQUIRED",
    "transport": "TRANSPORT",
    "timeout": "TIMEOUT",
    "server": "SERVER",
    "client": "CLIENT_ERROR",
    "empty": "EMPTY_RESPONSE",
    "aborted": "ABORTED",
}


class UpstreamError(Exception):
    def __init__(self, message: str, code: str, **details: Any):
        super().__init__(message)
        self.message = message
        self.code = code
        for key, value in details.items():
            setattr(self, key, value)


def _cause(error: BaseException) -> str:
    return str(error) if str(error) else error.__class__.__name__


def classify_failure(status: int | None, payload: Any, retry_after_ms: int | None = None) -> UpstreamError:
    """把网关的 JSON 错误信封转成已分类的失败。"""
    error = (payload.get("error") if isinstance(payload, dict) else None) or (payload if isinstance(payload, dict) else {}) or {}
    etype = error.get("type") if isinstance(error.get("type"), str) else ""
    raw = error.get("message") if isinstance(error.get("message"), str) else f"upstream HTTP {status}"
    raw_html = bool(__import__("re").match(r"^\s*<(!doctype|html[\s>])", raw, __import__("re").IGNORECASE))
    is_html = raw_html or "with an HTML error page" in raw
    message = (
        f"the gateway's front proxy answered HTTP {status} with an HTML error page — usually a WAF or "
        "body-size limit in front of the gateway, not your credentials"
        if raw_html else raw
    )
    flat = message.lower()
    if etype == "RegionError" or "not available in your country" in flat or "region" in flat:
        return UpstreamError(message, CODE["region"], status=status, type=etype)
    if status == 429 or etype == "FreeUsageLimitError" or "usage limit" in flat or "rate limit" in flat:
        return UpstreamError(message, CODE["quota"], status=status, type=etype, providerRetryAfterMs=retry_after_ms)
    if status in (401, 403) and ("signature rejected" in flat or "signature mismatch" in flat):
        return UpstreamError(
            "the gateway rejected the request signature — the request body was modified in transit; "
            "if a local proxy plugin is installed, disable it for this lane or enable its passthrough for signed requests",
            CODE["transport"], status=status, type=etype, signatureRejected=True,
        )
    if etype == "AuthorizationRequired" or "需要 GitHub 授权" in raw or "GitHub 授权无效" in raw:
        return UpstreamError(message, CODE["authorization"], status=status, type=etype,
                             reason=error.get("reason") if isinstance(error.get("reason"), str) else "")
    if status in (401, 403):
        return UpstreamError(message, CODE["client"] if is_html else CODE["credential"], status=status, type=etype)
    if etype == "ModelError" or "model is unavailable" in flat or "not supported" in flat:
        return UpstreamError(message, CODE["server"], status=status, type=etype, unavailable=True)
    if isinstance(status, int) and 400 <= status < 500 and status not in (408, 425):
        return UpstreamError(message, CODE["client"], status=status, type=etype)
    return UpstreamError(message, CODE["server"], status=status, type=etype)


SNIFF_BYTES = 4096


def sniff_body(text: str) -> str:
    """按形状对响应体开头分类：sse / json / empty / unknown。"""
    head = str(text or "").lstrip("\ufeff").lstrip()
    if head == "":
        return "empty"
    if head.startswith(":") or __import__("re").search(r"^(?:data|event|id|retry)[ \t]*:", head[:64], __import__("re").MULTILINE):
        return "sse"
    if head.startswith("{") or head.startswith("["):
        return "json"
    return "unknown"


@dataclass
class Head:
    chunks: list[bytes] = field(default_factory=list)
    done: bool = False
    text: str = ""
    source: AsyncIterator[bytes] | None = None


async def _next(source: AsyncIterator[bytes], timeout_s: float) -> bytes | None:
    """取下一块；到点无字节则抛超时。返回 None 表示结束。"""
    try:
        return await asyncio.wait_for(source.__anext__(), timeout=timeout_s)
    except StopAsyncIteration:
        return None
    except asyncio.TimeoutError:
        raise UpstreamError("our-free-model: upstream sent no bytes before its deadline", CODE["timeout"])
    except asyncio.CancelledError:
        raise UpstreamError("request aborted", CODE["aborted"])


async def read_head(source: AsyncIterator[bytes], limit: int, timeout_s: float) -> Head:
    """读前 ``limit`` 字节而不丢其后内容；一旦判定为流就立即返回。"""
    head = Head(source=source)
    size = 0
    try:
        while size < limit:
            chunk = await _next(source, timeout_s)
            if chunk is None:
                head.done = True
                break
            head.chunks.append(chunk)
            size += len(chunk)
            head.text = b"".join(head.chunks).decode("utf-8", "ignore")
            if sniff_body(head.text) == "sse":
                break
    except UpstreamError:
        raise
    return head


async def _replay(head: Head) -> AsyncIterator[bytes]:
    for chunk in head.chunks:
        yield chunk
    if head.done or head.source is None:
        return
    async for chunk in head.source:
        yield chunk


async def _read_remainder(head: Head) -> bytes:
    data = b"".join(head.chunks)
    if head.done or head.source is None:
        return data
    async for chunk in head.source:
        data += chunk
    return data


def _emit(line: str, on_data: Callable[[str], None]) -> None:
    text = line.strip()
    if text == "" or text.startswith(":"):
        return
    if text.startswith("data:"):
        payload = text[5:].strip()
        if payload == "" or payload == "[DONE]":
            return
        on_data(payload)


async def read_sse(source: AsyncIterator[bytes], on_data: Callable[[str], None], timeout_s: float = 300.0) -> None:
    """把 SSE 字节流拆成 ``data:`` 负载字符串；注释行忽略。"""
    buffer = ""
    deadline = time.monotonic() + timeout_s
    try:
        async for chunk in source:
            if time.monotonic() > deadline:
                raise UpstreamError("our-free-model: upstream stream idle past its deadline", CODE["timeout"])
            buffer += chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                _emit(line, on_data)
            deadline = time.monotonic() + timeout_s
        _emit(buffer, on_data)
    except UpstreamError:
        raise
    except (httpx.HTTPError, OSError) as error:
        raise UpstreamError(f"our-free-model: upstream stream read failed: {_cause(error)}", CODE["transport"])


# ── HTTP 客户端 ─────────────────────────────────────────────────────────────

_client: httpx.AsyncClient | None = None
_client_lock = asyncio.Lock()


def _ssl_context():
    """优先使用操作系统证书库（Windows 会加载系统根证书）。

    缺少本地 CA（企业代理/MITM）时可用 ``OFM_TLS_VERIFY=0`` 关闭校验。
    """
    import ssl

    context = ssl.create_default_context()
    value = (os.environ.get("OFM_TLS_VERIFY", "1") or "1").strip().lower()
    if value in ("0", "false", "no", "off"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    timeout=httpx.Timeout(connect=15.0, read=300.0, write=60.0, pool=15.0),
                    follow_redirects=False,
                    verify=_ssl_context(),
                    limits=httpx.Limits(max_connections=64, max_keepalive_connections=16),
                )
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _user_agent_with(attribution: str | None) -> str:
    if not attribution:
        return CLIENT_UA
    return attribution if "opencode/" in attribution else f"{attribution} {CLIENT_UA}"


async def post_streamed(
    path: str,
    body: dict,
    session: str,
    request_id: str,
    attribution_user_agent: str | None,
    on_data: Callable[[str], None],
    timeout_ms: int = 300000,
) -> httpx.Response:
    """POST 一次请求并把解码后的 SSE ``data:`` 负载逐个回调。"""
    headers = gateway_headers(truncate_session(session), request_id, True)
    headers["user-agent"] = _user_agent_with(attribution_user_agent)
    client = await get_client()
    timeout_s = max(1.0, timeout_ms / 1000.0)
    try:
        async with client.stream(
            "POST", f"{UPSTREAM_BASE}{path}", headers=headers,
            content=json.dumps(body), timeout=httpx.Timeout(connect=15.0, read=timeout_s, write=60.0, pool=15.0),
        ) as response:
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                try:
                    payload = json.loads(text)
                except ValueError:
                    payload = {"error": {"message": text[:300] or f"HTTP {response.status_code}"}}
                raise classify_failure(response.status_code, payload)
            head = await read_head(response.aiter_bytes(), SNIFF_BYTES, timeout_s)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("our-free-model: upstream returned no body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), on_data, timeout_s)
                return response
            text = (await _read_remainder(head)).decode("utf-8", "replace")
            if shape != "json":
                raise UpstreamError(f"our-free-model: unexpected non-SSE response: {text[:200]}", CODE["server"],
                                    status=response.status_code)
            try:
                payload = json.loads(text)
            except ValueError:
                raise UpstreamError(f"our-free-model: unexpected non-SSE response: {text[:200]}", CODE["server"],
                                    status=response.status_code)
            if isinstance(payload, dict) and payload.get("error"):
                raise classify_failure(response.status_code, payload)
            on_data(json.dumps(payload))
            return response
    except UpstreamError:
        raise
    except asyncio.CancelledError:
        raise UpstreamError("request aborted", CODE["aborted"])
    except httpx.TimeoutException as error:
        raise UpstreamError(f"our-free-model: upstream request timed out: {_cause(error)}", CODE["timeout"])
    except httpx.HTTPError as error:
        raise UpstreamError(f"our-free-model: upstream request failed: {_cause(error)}", CODE["transport"])


async def get_json(
    path: str,
    session: str | None = None,
    request_id: str | None = None,
    attribution_user_agent: str | None = None,
    timeout_ms: int = 15000,
) -> Any:
    """用指纹头拉取一个小的 JSON 文档。"""
    headers = gateway_headers(truncate_session(session or ""), request_id or "", False, "application/json")
    headers["user-agent"] = _user_agent_with(attribution_user_agent)
    client = await get_client()
    try:
        response = await client.get(f"{UPSTREAM_BASE}{path}", headers=headers,
                                    timeout=timeout_ms / 1000.0)
        text = response.text
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {"error": {"message": text[:200]}}
        if response.status_code >= 400:
            raise classify_failure(response.status_code, payload)
        return payload
    except UpstreamError:
        raise
    except asyncio.CancelledError:
        raise UpstreamError("request aborted", CODE["aborted"])
    except httpx.TimeoutException:
        raise UpstreamError("our-free-model: upstream GET timed out", CODE["timeout"])
    except httpx.HTTPError as error:
        raise UpstreamError(f"our-free-model: upstream GET failed: {_cause(error)}", CODE["transport"])
