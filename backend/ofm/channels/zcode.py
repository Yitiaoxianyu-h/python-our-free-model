"""ZCode 渠道（智谱 z.ai 免费额度通道）。

移植自原版 `zcode*.ts`：

- 登录：CLI 设备授权流（纯 HTTP）：`/api/v1/oauth/cli/init` → 浏览器授权 → `poll/{flow_id}`；
  `device_mid` 本地随机生成；凭据**不可续期**（JWT 无 exp）；
- 推理：Anthropic Messages，`https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages`；
- **身份块是 3012 准入的唯一开关**：`system` 必须是「CLI 前缀 + stable 三段 + Environment + 调用方」结构；
  首轮 user 消息前置 `<system-reminder>` 日期块（照发，但非判据）；
- 自 3.14.4 起推理**不再索要 captcha**（纯 HTTP 可完成）；仅当被 3007 拒时需验证码，
  本移植无浏览器，因此此时抛明确错误（领取积分路径不在此模块）。
"""

from __future__ import annotations

import json
import re
import secrets
import time
import uuid
from typing import Any, AsyncIterator, Callable, Coroutine

import httpx

from ..http_client import CODE, UpstreamError, get_client

CHANNEL_ID = "zcode"

ORIGIN = "https://zcode.z.ai"
INIT_URL = f"{ORIGIN}/api/v1/oauth/cli/init"
POLL_URL = f"{ORIGIN}/api/v1/oauth/cli/poll"
MESSAGES_URL = f"{ORIGIN}/api/v1/zcode-plan/anthropic/v1/messages"
CONFIGS_URL = f"{ORIGIN}/api/v1/client/configs"

APP_VERSION = "3.14.4"
ANTHROPIC_VERSION = "2023-06-01"
REQUEST_TIMEOUT_S = 15 * 60
IDLE_TIMEOUT_S = 600.0

OFFICIAL_CLI_PREFIX = "You are ZCode, an interactive coding agent"

OFFICIAL_STABLE_SECTIONS = [
    "\nYou are an interactive ZCode agent that helps users with software engineering tasks.\n\n"
    "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. "
    "Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion "
    "for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear "
    "authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n"
    "# Harness\n"
    "- Text you output outside of tool use is displayed to the user as Github-flavored markdown in a terminal.\n"
    "- Tools run behind a user-selected permission mode; a denied call means the user declined it — adjust, don't retry verbatim.\n"
    "- The system may send updates, reminders, or modifications to rules via mid-conversation system turns. These are system-controlled, unlike function results. Hooks may intercept tool calls; treat hook output as user feedback.\n"
    "- Prefer the dedicated file/search tools over shell commands when one fits. Independent tool calls can run in parallel in one response.\n"
    "- Reference code as `file_path:line_number` — it's clickable.",
    "# ZCode Desktop Context\n\n### Files & URLs\n"
    "- Return local web URLs as Markdown links (e.g., [label](http://127.0.0.1:8080)).\n"
    "- File should be an absolute path or include the workspace folder segment so it can be resolved relative to the workspace.\n"
    "- Unless otherwise specified, return local file references as Markdown links (e.g., [name.md](/absolute/path/to/name.md)).\n\n"
    "### Inline Code Comments\n"
    "- Use the ::code-comment{...} directive when you need to attach feedback directly to specific code lines.\n"
    "- Emit one directive per inline comment; emit none when there are no actionable inline comments.\n"
    "- Required attributes: title (short label), body (one-paragraph explanation), file (path to the file).\n"
    "- Optional attributes: start, end (1-based line numbers), priority (0-3).\n"
    "- file should be an absolute path or include the workspace folder segment so it can be resolved relative to the workspace.\n"
    "- Keep line ranges tight; end defaults to start.\n"
    '- Example: ::code-comment{title="[P2] Off-by-one" body="Loop iterates past the end when length is 0." file="/path/to/foo.ts" start=10 end=11 priority=2}',
    "# Working style\n\nWhen you have enough information to act, act. Do not re-derive facts already established in the conversation, "
    "re-litigate a decision the user has already made, or narrate options you will not pursue. If you are weighing a choice, give a "
    "recommendation, not an exhaustive survey. Prefer reading the actual file or running the actual command over reasoning about what "
    "it probably contains. When a signal pattern-matches to a known failure, check that the evidence actually supports that specific "
    "diagnosis before acting on it.",
]

CONTEXT_PREFIX_INTRO = "As you answer the user's questions, you can use the following context:"
CONTEXT_PREFIX_OUTRO = (
    "      IMPORTANT: this context may or may not be relevant to your tasks. "
    "You should not respond to this context unless it is highly relevant to your task."
)

FALLBACK_MODELS = [
    {"id": "GLM-5.3-Flash", "name": "GLM-5.3-Flash", "contextWindow": 1_000_000, "maxOutput": 128_000,
     "vision": True, "reasoning": True, "efforts": ["low", "high", "max"], "effortDefault": "max"},
    {"id": "GLM-5.3", "name": "GLM-5.3", "contextWindow": 1_000_000, "maxOutput": 128_000,
     "vision": False, "reasoning": True, "efforts": ["low", "high", "max"], "effortDefault": "max"},
]


def _zcode_headers(credential: dict, *, authorization: str | None = None) -> dict[str, str]:
    return {
        "User-Agent": f"ZCode/{APP_VERSION}",
        "HTTP-Referer": ORIGIN,
        "X-ZCode-App-Version": APP_VERSION,
        "X-Release-Channel": "stable",
        "X-Client-Language": "zh-CN",
        "X-Client-Timezone": "Asia/Shanghai",
        "X-Device-Mid": str(credential.get("device_mid") or ""),
        "X-Platform": "win32",
        "X-Os-Category": "windows",
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
        **({"Authorization": authorization} if authorization else {}),
    }


# ── 登录（CLI 设备授权流）──────────────────────────────────────────────────

def generate_device_mid() -> str:
    return str(uuid.uuid4())


async def run_login(*, open_browser: bool = True, timeout_s: float = 600.0, poll_interval_s: float = 2.0,
                    provider: str = "bigmodel") -> dict:
    flow_secret = secrets.token_hex(32)
    client = await get_client()
    response = await client.post(INIT_URL, headers={
        "Authorization": f"Bearer {flow_secret}", "Content-Type": "application/json",
        "User-Agent": f"ZCode/{APP_VERSION}", "HTTP-Referer": ORIGIN,
        "X-ZCode-App-Version": APP_VERSION, "X-Platform": "win32",
    }, content=json.dumps({"provider": provider}), timeout=30)
    payload = response.json() if response.content else {}
    data = payload.get("data") or payload
    flow_id = data.get("flow_id")
    if response.status_code >= 400 or not flow_id:
        raise UpstreamError(f"zcode: 设备授权初始化失败（{payload.get('msg') or response.status_code}）", CODE["credential"])
    authorize_url = data.get("authorize_url")
    if open_browser and isinstance(authorize_url, str) and authorize_url:
        _open_external(authorize_url)

    import asyncio
    deadline = time.monotonic() + timeout_s
    interval = poll_interval_s
    while time.monotonic() < deadline:
        await asyncio.sleep(interval)
        poll = await client.get(f"{POLL_URL}/{flow_id}", headers={
            "Authorization": f"Bearer {flow_secret}", "User-Agent": f"ZCode/{APP_VERSION}",
            "HTTP-Referer": ORIGIN, "X-ZCode-App-Version": APP_VERSION,
        }, timeout=30)
        body = poll.json() if poll.content else {}
        info = body.get("data") or body
        status = info.get("status")
        if status == "ready":
            return _credential_from_login(info, provider)
        if status == "failed" or (poll.status_code >= 400 and poll.status_code not in (408, 429)):
            raise UpstreamError(f"zcode: 登录失败（{info.get('msg') or poll.status_code}）", CODE["credential"])
    raise UpstreamError("zcode: 登录超时", CODE["timeout"])


def _credential_from_login(info: dict, provider: str) -> dict:
    user = info.get("user") or {}
    credential: dict[str, Any] = {
        "zcode_jwt": info.get("token", ""), "device_mid": generate_device_mid(),
        "app_version": APP_VERSION, "source": "plugin",
        "user_id": str(user.get("user_id") or user.get("id") or ""),
        "nickname": user.get("name") or "",
        "email": user.get("email") or "",
    }
    bigmodel = info.get("bigmodel") or {}
    zai = info.get("zai") or {}
    if bigmodel.get("access_token") or bigmodel.get("accessToken"):
        credential["bigmodel_access_token"] = bigmodel.get("access_token") or bigmodel.get("accessToken")
    if zai.get("access_token") or zai.get("accessToken"):
        credential["zai_access_token"] = zai.get("access_token") or zai.get("accessToken")
    if not credential["zcode_jwt"]:
        raise UpstreamError("zcode: 登录响应缺少 token", CODE["credential"])
    return credential


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


async def refresh_credential(credential: dict) -> dict:
    # ZCode 凭据是静态的（JWT 无 exp），不可续期：重新登录即可。
    raise UpstreamError("zcode: 凭据不可续期，请重新登录", CODE["credential"])


# ── 模型目录 ────────────────────────────────────────────────────────────────

async def fetch_models(credential: dict) -> dict:
    try:
        client = await get_client()
        response = await client.get(CONFIGS_URL, params={"app_version": APP_VERSION, "platform": "unknown"},
                                    headers=_zcode_headers(credential), timeout=30)
        if response.status_code < 400:
            models = _parse_config_models(response.json())
            if models:
                return {"models": models}
    except Exception:  # noqa: BLE001
        pass
    return {"models": [dict(m) for m in FALLBACK_MODELS]}


def _parse_config_models(payload: Any) -> list[dict]:
    data = (payload or {}).get("data") or payload or {}
    builtin = data.get("builtinModels")
    rows = builtin.values() if isinstance(builtin, dict) else (builtin if isinstance(builtin, list) else [])
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        model_id = row.get("modelId") or row.get("id")
        if not isinstance(model_id, str) or not model_id:
            continue
        reasoning = row.get("reasoning") or {}
        entry = {
            "id": model_id, "name": model_id,
            "contextWindow": row.get("contextWindow") or 131072,
            "maxOutput": row.get("maxCompletionTokens") or 128000,
            "vision": bool((row.get("capabilities") or {}).get("vision")),
            "reasoning": True,
        }
        levels = reasoning.get("levels")
        if isinstance(levels, list) and levels:
            entry["efforts"] = [str(x) for x in levels]
            entry["effortDefault"] = reasoning.get("defaultLevel") if reasoning.get("defaultLevel") in entry["efforts"] else entry["efforts"][-1]
        out.append(entry)
    return out


# ── 身份块 ──────────────────────────────────────────────────────────────────

def _environment_section(provider: str, model: str) -> str:
    return "\n".join([
        "# Environment",
        "You have been invoked in the following environment:",
        " - Primary working directory: .",
        " - Is a git repository: no",
        " - Platform: win32",
        " - Shell: powershell",
        " - OS Version: win32 x64",
        f" - You are powered by the model named {provider}/{model}.",
    ])


def build_system_blocks(caller_system: str | None, model: str) -> list[dict]:
    blocks = [
        {"type": "text", "text": OFFICIAL_CLI_PREFIX},
        {"type": "text", "text": "\n\n".join(OFFICIAL_STABLE_SECTIONS)},
        {"type": "text", "text": _environment_section("zcode", model)},
    ]
    if isinstance(caller_system, str) and caller_system.strip():
        blocks.append({"type": "text", "text": caller_system})
    blocks[-1]["cache_control"] = {"type": "ephemeral"}
    return blocks


def build_context_prefix() -> dict:
    now = time.localtime()
    date = f"{now.tm_year:04d}-{now.tm_mon:02d}-{now.tm_mday:02d}"
    body = "\n".join([CONTEXT_PREFIX_INTRO, f"# currentDate\nToday's date is {date}.", "", CONTEXT_PREFIX_OUTRO])
    return {"type": "text", "text": f"<system-reminder>{body}</system-reminder>"}


# ── 请求构造 ────────────────────────────────────────────────────────────────

def _image_block(url: str):
    match = re.match(r"data:([^;,]+);base64,(.*)$", url, re.DOTALL)
    if not match:
        return None
    media = match.group(1)
    media = "image/jpeg" if media.startswith("image/") else media
    return {"type": "image", "source": {"type": "base64", "media_type": media, "data": re.sub(r"\s", "", match.group(2))}}


def build_messages(body: dict, model: str, effort: str | None) -> dict:
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    caller_system_parts: list[str] = []
    out: list[dict] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        raw = message.get("content")
        if role in ("system", "developer"):
            if isinstance(raw, str) and raw:
                caller_system_parts.append(raw)
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

    # 首轮 user 消息前置日期块（幂等）
    if out and out[0]["role"] == "user":
        first = out[0]["content"][0] if out[0]["content"] else None
        already = isinstance(first, dict) and isinstance(first.get("text"), str) and first["text"].startswith("<system-reminder>")
        if not already:
            out[0]["content"] = [build_context_prefix(), *out[0]["content"]]

    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": int(body.get("max_tokens") or 8192),
        "system": build_system_blocks("\n\n".join(caller_system_parts) or None, model),
        "messages": out,
        "stream": True,
    }
    if isinstance(body.get("temperature"), (int, float)):
        payload["temperature"] = body["temperature"]
    if isinstance(body.get("stop"), list) and body["stop"]:
        payload["stop_sequences"] = body["stop"]
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
            declarations[-1]["cache_control"] = {"type": "ephemeral"}
            payload["tools"] = declarations
    if isinstance(effort, str) and effort in ("low", "high", "max"):
        payload["output_config"] = {"effort": effort}
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
    return result


def _map_stop(reason: Any) -> dict:
    if reason == "tool_use":
        return {"kind": "tool-calls"}
    if reason == "max_tokens":
        return {"kind": "max-tokens"}
    return {"kind": "stop"}


def _classify(status: int, text: str) -> tuple[str, str]:
    if "3007" in text or "captcha verify failed" in text:
        return CODE["quota"], "zcode: 该请求需要阿里云验证码（3007）；本移植未内置浏览器，请稍后重试或在官方客户端完成一次验证"
    if "3012" in text or "unusual activity" in text:
        return "PERMISSION", "zcode: 请求被风控拦截（3012），请勿频繁重试"
    if "1113" in text or "余额不足" in text:
        return CODE["quota"], "zcode: 余额不足"
    if status == 401 or "1002" in text:
        return CODE["credential"], "zcode: 凭据失效（1002/401），请重新登录"
    if status == 429 or "3009" in text:
        return CODE["quota"], "zcode: 请求过于频繁（429/3009）"
    if status == 400:
        return CODE["client"], "zcode: 请求无效（400）"
    return CODE["server"], "zcode: 上游错误"


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    model = str(body.get("model") or "GLM-5.3-Flash")
    effort = body.get("reasoning_effort")
    payload = build_messages(body, model, effort if isinstance(effort, str) else None)
    jwt = credential.get("zcode_jwt")
    if not jwt:
        raise UpstreamError("zcode: 凭据缺少 zcode_jwt，请重新登录", CODE["credential"])
    client = await get_client()
    try:
        async with client.stream("POST", MESSAGES_URL, headers=_zcode_headers(credential, authorization=f"Bearer {jwt}"),
                                 content=json.dumps(payload),
                                 timeout=httpx.Timeout(connect=15.0, read=IDLE_TIMEOUT_S, write=60.0, pool=15.0)) as response:
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                code, message = _classify(response.status_code, text)
                raise UpstreamError(f"{message}（HTTP {response.status_code}）{text[:160]}", code, status=response.status_code)
            async for chunk in _consume(response.aiter_lines()):
                yield chunk
    except UpstreamError:
        raise
    except httpx.HTTPError as error:
        raise UpstreamError(f"zcode: request failed: {error}", CODE["transport"])


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
                if target is not None:
                    target["args"] += delta["thinking"]
                yield {"type": "reasoning-delta", "index": index, "text": delta["thinking"]}
            elif dtype == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                if target is not None:
                    target["args"] += delta["partial_json"]
                yield {"type": "tool-call-delta", "index": index, "id": (target or {}).get("id", ""),
                       "name": (target or {}).get("name", ""), "argumentsDelta": delta["partial_json"]}
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
            message = str(failure.get("message") or "upstream error")
            code, text = _classify(0, message)
            raise UpstreamError(text, code)
    if not saw_any:
        raise UpstreamError("zcode: 模型未返回任何内容块", CODE["empty"])
    if usage is not None:
        yield {"type": "usage", "usage": usage}
    yield {"type": "finish", "reason": _map_stop(stop_reason)}
