"""MiniMax Code 渠道。

移植自原版 `minimax*.ts`：

- 登录：OAuth 设备码 + PKCE（S256），client_id ``mcode-public``、audience ``agent-backend``、scope ``agent.default``；
- 推理：**Anthropic Messages 协议族**，``POST https://agent.minimax.cn/mavis/api/v1/llm/v1/messages``，
  请求头只带 Authorization + Content-Type + Accept（**不发 anthropic-version**）；
- SSE 为 Anthropic 事件流（message_start / content_block_delta / message_delta …），thinking 走 ``thinking_delta``，签名帧忽略；
- 图片为 Anthropic ``image.source.base64``（裸 base64，OpenAI 的 image_url 会被服务端拒绝）；
- HTTP 402 = 余额不足 → QUOTA_EXCEEDED（不重试）。

注：MiniMax-M3.1 系对 ``thinking`` 强制 adaptive，必须走 ``output_config.effort``。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from typing import Any, AsyncIterator, Callable
from urllib.parse import urlencode

import httpx

from ..http_client import CODE, UpstreamError, get_client

CHANNEL_ID = "minimax"

ACCOUNT_HOST = "https://account.minimax.cn"
API_HOST = "https://agent.minimax.cn"
DEVICE_CODE_PATH = "/oauth2/device/code"
TOKEN_PATH = "/oauth2/token"
MODELS_PATH = "/mavis/api/v1/models"
INFER_PATH = "/mavis/api/v1/llm/v1/messages"

CLIENT_ID = "mcode-public"
AUDIENCE = "agent-backend"
SCOPE = "agent.default"

REQUEST_TIMEOUT_S = 30
OAUTH_TIMEOUT_S = 20
MAX_IMAGE_BYTES = 10 * 1024 * 1024
ADAPTIVE_ONLY_PREFIX = "MiniMax-M3.1"

EFFORT_OPTIONS = ["default", "low", "medium", "high", "xhigh", "max"]

FALLBACK_MODELS = [
    {"id": "MiniMax-M3.1-Flash-Preview", "name": "M3.1-Flash-Preview", "contextWindow": 1_000_000,
     "maxOutput": 128_000, "vision": True, "reasoning": True, "efforts": EFFORT_OPTIONS, "effortDefault": "default"},
    {"id": "MiniMax-M3", "name": "M3", "contextWindow": 1_000_000, "maxOutput": 128_000,
     "vision": True, "reasoning": True},
    {"id": "MiniMax-M2.7-highspeed", "name": "M2.7-highspeed", "contextWindow": 200_000, "maxOutput": 128_000,
     "vision": False, "reasoning": True},
    {"id": "MiniMax-M2.7", "name": "M2.7", "contextWindow": 200_000, "maxOutput": 128_000,
     "vision": False, "reasoning": True},
]


# ── OAuth 设备码 ────────────────────────────────────────────────────────────

def _pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _parse_token_grant(payload: dict, previous_refresh: str | None) -> dict:
    access = payload.get("access_token")
    if not isinstance(access, str) or not access:
        raise UpstreamError("minimax: 令牌响应缺少 access_token", CODE["credential"])
    refresh = payload.get("refresh_token") or previous_refresh
    if not isinstance(refresh, str) or not refresh:
        raise UpstreamError("minimax: 令牌响应缺少 refresh_token", CODE["credential"])
    token_type = str(payload.get("token_type") or "").lower()
    if token_type != "bearer":
        raise UpstreamError(f"minimax: 令牌类型不是 bearer（{token_type}）", CODE["credential"])
    try:
        expires_in = float(payload.get("expires_in"))
    except (TypeError, ValueError):
        expires_in = 0
    if expires_in <= 0:
        raise UpstreamError("minimax: 令牌响应缺少有效的 expires_in", CODE["credential"])
    scope = str(payload.get("scope") or "")
    if SCOPE not in scope:
        raise UpstreamError(f"minimax: 令牌响应的 scope 不含 {SCOPE}", CODE["credential"])
    return {
        "access_token": access, "refresh_token": refresh, "token_type": "Bearer",
        "scope": scope, "expires_at": str(int(time.time() * 1000 + expires_in * 1000)),
    }


async def _post_form(path: str, form: dict) -> httpx.Response:
    client = await get_client()
    return await client.post(f"{ACCOUNT_HOST}{path}",
                             headers={"Accept": "application/json",
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             content=urlencode(form), timeout=OAUTH_TIMEOUT_S)


async def refresh_credential(credential: dict) -> dict:
    refresh_token = credential.get("refresh_token")
    if not refresh_token:
        raise UpstreamError("minimax: 凭据没有 refresh_token，请重新登录", CODE["credential"])
    response = await _post_form(TOKEN_PATH, {
        "grant_type": "refresh_token", "refresh_token": refresh_token,
        "client_id": CLIENT_ID, "scope": SCOPE, "audience": AUDIENCE,
    })
    payload = response.json() if response.content else {}
    if response.status_code >= 400:
        error = str(payload.get("error") or response.status_code)
        if re.search(r"invalid_grant|expired|revoked", error, re.IGNORECASE):
            raise UpstreamError("minimax: refresh token 已失效，请重新登录", CODE["credential"])
        raise UpstreamError(f"minimax: 续期失败：{error}", CODE["credential"])
    return _parse_token_grant(payload, refresh_token)


async def run_login(*, open_browser: bool = True, timeout_s: int = 600) -> dict:
    verifier, challenge = _pkce()
    response = await _post_form(DEVICE_CODE_PATH, {
        "client_id": CLIENT_ID, "scope": SCOPE, "audience": AUDIENCE,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    payload = response.json() if response.content else {}
    device_code = payload.get("device_code")
    if response.status_code >= 400 or not device_code:
        raise UpstreamError(f"minimax: 设备码申请失败：{payload.get('error') or response.status_code}", CODE["credential"])
    uri = payload.get("verification_uri_complete") or payload.get("verification_uri") or payload.get("verification_url")
    if open_browser and isinstance(uri, str) and uri:
        _open_external(uri)
    expires_in = payload.get("expires_in") or 600
    interval = payload.get("interval") or 5
    deadline = time.monotonic() + min(int(expires_in), timeout_s)
    import asyncio
    while time.monotonic() < deadline:
        await asyncio.sleep(interval)
        poll = await _post_form(TOKEN_PATH, {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code, "client_id": CLIENT_ID, "code_verifier": verifier,
        })
        body = poll.json() if poll.content else {}
        status = body.get("status") if isinstance(body, dict) else None
        error = body.get("error") if isinstance(body, dict) else None
        if status in ("pending",) or error == "authorization_pending":
            continue
        if status == "slow_down" or error == "slow_down":
            interval += 5
            continue
        if status in ("denied", "access_denied"):
            raise UpstreamError("minimax: 登录被拒绝", CODE["aborted"])
        if status in ("expired", "expired_token") or error in ("expired_token",):
            raise UpstreamError("minimax: 设备码已过期", CODE["timeout"])
        if poll.status_code < 400 and "access_token" in body:
            return _parse_token_grant(body, None)
        if error:
            raise UpstreamError(f"minimax: 登录失败：{error}", CODE["credential"])
    raise UpstreamError("minimax: 登录超时", CODE["timeout"])


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


def is_expired(credential: dict) -> bool:
    raw = credential.get("expires_at")
    if not isinstance(raw, str) or not raw.isdigit():
        return False
    value = int(raw)
    if value < 10**12:
        value *= 1000
    return value - 60_000 <= time.time() * 1000


# ── 模型目录 ────────────────────────────────────────────────────────────────

async def fetch_models(credential: dict) -> dict:
    token = credential.get("access_token")
    if not token:
        return {"models": [dict(m) for m in FALLBACK_MODELS]}
    client = await get_client()
    try:
        response = await client.get(f"{API_HOST}{MODELS_PATH}", params={"region": "cn", "buildEnv": "prod"},
                                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                                    timeout=REQUEST_TIMEOUT_S)
        if response.status_code >= 400:
            return {"models": [dict(m) for m in FALLBACK_MODELS]}
        return {"models": _parse_models(response.json()) or [dict(m) for m in FALLBACK_MODELS]}
    except Exception:  # noqa: BLE001
        return {"models": [dict(m) for m in FALLBACK_MODELS]}


def _parse_models(payload: Any) -> list[dict]:
    models: dict[str, dict] = {}
    order: list[str] = []
    for provider in (payload or {}).get("providers") or []:
        config = provider.get("config") or {}
        for model_id, row in (config.get("models") or {}).items():
            row = row if isinstance(row, dict) else {}
            limit = row.get("limit") or {}
            context = limit.get("context") or 131072
            options = row.get("context_window_options")
            if isinstance(options, list) and options:
                context = max(v for v in options if isinstance(v, int)) if any(isinstance(v, int) for v in options) else context
            modalities = (row.get("modalities") or {}).get("input") or []
            entry = {"id": model_id, "name": row.get("name") or model_id,
                     "contextWindow": context if isinstance(context, int) else 131072,
                     "maxOutput": limit.get("output") if isinstance(limit.get("output"), int) else 128000,
                     "vision": "image" in modalities, "reasoning": True}
            efforts = row.get("effort_options")
            if isinstance(efforts, list) and efforts:
                entry["efforts"] = [e for e in efforts if isinstance(e, str)]
                entry["effortDefault"] = row.get("default_effort") if row.get("default_effort") in entry["efforts"] else entry["efforts"][0]
            models[model_id] = entry
        order.extend(config.get("model_order") or [])
    ordered = [models[mid] for mid in order if mid in models]
    ordered.extend(entry for mid, entry in models.items() if mid not in order)
    return ordered


# ── 推理 ────────────────────────────────────────────────────────────────────

def _image_block(url: str):
    match = re.match(r"data:([^;,]+);base64,(.*)$", url, re.DOTALL)
    if not match:
        return None
    media, data = match.group(1), re.sub(r"\s", "", match.group(2))
    if len(data) * 3 // 4 > MAX_IMAGE_BYTES:
        raise UpstreamError("minimax: 图片超过 10MB 上限", CODE["client"])
    return {"type": "image", "source": {"type": "base64", "media_type": media or "image/png", "data": data}}


def build_messages(body: dict) -> dict:
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    out: list[dict] = []
    system_parts: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        raw = message.get("content")
        if role in ("system", "developer"):
            if isinstance(raw, str) and raw:
                system_parts.append(raw)
            continue
        if role == "tool":
            text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
            block = {"type": "tool_result", "tool_use_id": message.get("tool_call_id", ""),
                     "content": [{"type": "text", "text": text or "(no output)"}]}
            if out and out[-1]["role"] == "user":
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
            continue
        blocks: list[dict] = []
        if isinstance(raw, str):
            if raw:
                blocks.append({"type": "text", "text": raw})
        elif isinstance(raw, list):
            for part in raw:
                if not isinstance(part, dict):
                    continue
                if part.get("type") in ("text", "input_text") and part.get("text"):
                    blocks.append({"type": "text", "text": part["text"]})
                elif part.get("type") == "image_url":
                    url = part.get("image_url")
                    url = url.get("url") if isinstance(url, dict) else url
                    if isinstance(url, str):
                        image = _image_block(url)
                        if image:
                            blocks.append(image)
        if role == "assistant":
            for call in message.get("tool_calls") or []:
                fn = call.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {}
                blocks.append({"type": "tool_use", "id": call.get("id", ""), "name": fn.get("name", ""), "input": args})
        if not blocks:
            continue
        mapped = "assistant" if role == "assistant" else "user"
        if out and out[-1]["role"] == mapped:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": mapped, "content": blocks})

    payload: dict[str, Any] = {"model": body.get("model", ""), "stream": True, "messages": out}
    if isinstance(body.get("max_tokens"), int):
        payload["max_tokens"] = body["max_tokens"]
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)
    if isinstance(body.get("temperature"), (int, float)):
        payload["temperature"] = body["temperature"]
    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        declarations = []
        for tool in tools:
            fn = tool.get("function") if isinstance(tool, dict) and isinstance(tool.get("function"), dict) else tool
            name = (fn or {}).get("name")
            if isinstance(name, str) and name:
                declarations.append({"name": name, "description": str(fn.get("description") or ""),
                                     "input_schema": fn.get("parameters") or {"type": "object", "properties": {}}})
        if declarations:
            payload["tools"] = declarations

    effort = body.get("reasoning_effort")
    model_id = str(body.get("model", ""))
    if effort == "none":
        payload["thinking"] = {"type": "disabled"}
    elif effort == "on":
        payload["thinking"] = {"type": "adaptive"}
    elif isinstance(effort, str) and effort in EFFORT_OPTIONS:
        payload["thinking"] = {"type": "adaptive"}
        payload["output_config"] = {"effort": effort}
    elif model_id.startswith(ADAPTIVE_ONLY_PREFIX):
        payload["thinking"] = {"type": "adaptive"}
    return payload


def _map_usage(usage: Any) -> dict | None:
    if not isinstance(usage, dict):
        return None
    inp = usage.get("input_tokens")
    out = usage.get("output_tokens")
    if inp is None and out is None:
        return None
    result = {"inputTokens": inp or 0, "outputTokens": out or 0, "totalTokens": (inp or 0) + (out or 0)}
    if usage.get("cache_read_input_tokens"):
        result["cacheReadTokens"] = usage["cache_read_input_tokens"]
    if usage.get("cache_creation_input_tokens"):
        result["cacheWriteTokens"] = usage["cache_creation_input_tokens"]
    thoughts = (usage.get("output_tokens_details") or {}).get("thinking_tokens")
    if thoughts:
        result["reasoningTokens"] = thoughts
    return result


def _map_stop(reason: Any) -> dict:
    if reason == "tool_use":
        return {"kind": "tool-calls"}
    if reason == "max_tokens":
        return {"kind": "max-tokens"}
    return {"kind": "stop"}


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    if is_expired(credential):
        credential = await refresh_credential(credential)
        if on_refresh is not None:
            on_refresh(credential)
    payload = build_messages(body)
    client = await get_client()
    headers = {"Authorization": f"Bearer {credential.get('access_token', '')}",
               "Content-Type": "application/json", "Accept": "text/event-stream"}
    url = f"{API_HOST}{INFER_PATH}"
    try:
        async with client.stream("POST", url, headers=headers, content=json.dumps(payload),
                                 timeout=httpx.Timeout(connect=15.0, read=600.0, write=60.0, pool=15.0)) as response:
            if response.status_code == 401:
                credential = await refresh_credential(credential)
                if on_refresh is not None:
                    on_refresh(credential)
                raise UpstreamError("minimax: 凭据已续期，请重试", CODE["credential"])
            if response.status_code == 402:
                raise UpstreamError("minimax: 账号余额不足（HTTP 402）", CODE["quota"], status=402)
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")[:300]
                code = CODE["client"] if response.status_code == 400 else (
                    CODE["credential"] if response.status_code in (401, 403) else
                    CODE["quota"] if response.status_code == 429 else CODE["server"])
                raise UpstreamError(f"minimax: HTTP {response.status_code} {text}", code, status=response.status_code)
            async for chunk in _consume(response.aiter_lines()):
                yield chunk
    except UpstreamError:
        raise
    except httpx.HTTPError as error:
        raise UpstreamError(f"minimax: request failed: {error}", CODE["transport"])


async def _consume(lines: AsyncIterator[str]) -> AsyncIterator[dict]:
    blocks: dict[int, dict] = {}
    saw_any = False
    usage = None
    stop_reason = None
    async for line in lines:
        line = line.strip()
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if raw in ("", "[DONE]"):
            continue
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        etype = event.get("type")
        if etype == "message_start":
            usage = _map_usage((event.get("message") or {}).get("usage")) or usage
        elif etype == "content_block_start":
            index = event.get("index", 0)
            block = event.get("content_block") or {}
            kind = block.get("type")
            if kind == "tool_use":
                blocks[index] = {"type": "tool-call", "id": block.get("id", ""), "name": block.get("name", ""), "args": ""}
                saw_any = True
                yield {"type": "block-start", "index": index, "blockType": "tool-call"}
            elif kind == "thinking":
                blocks[index] = {"type": "reasoning", "id": "", "name": "", "args": ""}
                saw_any = True
                yield {"type": "block-start", "index": index, "blockType": "reasoning"}
            else:
                blocks[index] = {"type": "text", "id": "", "name": "", "args": ""}
                yield {"type": "block-start", "index": index, "blockType": "text"}
        elif etype == "content_block_delta":
            index = event.get("index", 0)
            delta = event.get("delta") or {}
            dtype = delta.get("type")
            target = blocks.get(index)
            if dtype == "text_delta" and isinstance(delta.get("text"), str) and delta["text"]:
                saw_any = True
                if target is not None:
                    target["args"] += delta["text"]
                yield {"type": "text-delta", "index": index, "text": delta["text"]}
            elif dtype == "thinking_delta" and isinstance(delta.get("thinking"), str) and delta["thinking"]:
                saw_any = True
                yield {"type": "reasoning-delta", "index": index, "text": delta["thinking"]}
            elif dtype == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                if target is not None:
                    target["args"] += delta["partial_json"]
                yield {"type": "tool-call-delta", "index": index, "id": (target or {}).get("id", ""),
                       "name": (target or {}).get("name", ""), "argumentsDelta": delta["partial_json"]}
            # signature_delta 刻意忽略
        elif etype == "content_block_stop":
            index = event.get("index", 0)
            target = blocks.pop(index, None)
            if target is None:
                continue
            if target["type"] == "tool-call":
                yield {"type": "block-end", "index": index,
                       "block": {"type": "tool-call", "id": target["id"], "name": target["name"],
                                 "arguments": target["args"] or "{}"}}
            elif target["type"] == "reasoning":
                yield {"type": "block-end", "index": index, "block": {"type": "reasoning", "text": target["args"]}}
            else:
                yield {"type": "block-end", "index": index, "block": {"type": "text", "text": target["args"]}}
        elif etype == "message_delta":
            stop_reason = (event.get("delta") or {}).get("stop_reason") or stop_reason
            usage = _map_usage(event.get("usage")) or usage
        elif etype == "error":
            failure = event.get("error") or {}
            raise UpstreamError(f"minimax: {failure.get('message') or 'upstream error'}", CODE["server"])
    if not saw_any:
        raise UpstreamError("minimax: 模型未返回任何内容块", CODE["empty"])
    if usage is not None:
        yield {"type": "usage", "usage": usage}
    yield {"type": "finish", "reason": _map_stop(stop_reason)}
