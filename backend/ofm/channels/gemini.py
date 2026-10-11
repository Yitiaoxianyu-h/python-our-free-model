"""Gemini 渠道（Google Cloud Code Assist 免费线）。

移植自原版 `gemini*.ts`：

- 登录：Google OAuth（本地回调 + state 校验 + offline/consent），凭据带 refresh_token 可续期；
- 身份头：五个写死的 antigravity 头 + Bearer；流式请求**刻意不带** ``Accept``（与抓包一致）；
- 请求体：两层信封 ``{model, project, request:{...}}``，且**逐层字母序序列化**（上游对字段序敏感）；
- 响应：``/v1internal:streamGenerateContent?alt=sse``，帧为 ``{"response":{...}}`` 或裸 Response；
- ``thoughtSignature`` 跨轮状态：functionCall 上的签名落盘，下一轮按「工具名 + 规范化参数」回填；
- 模型表是静态的：``gemini-3.8-flash``，思考档位 low/medium/high/tiered。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import time
from typing import Any, AsyncIterator, Callable
from urllib.parse import quote, urlsplit

import httpx

from ..http_client import CODE, UpstreamError, get_client
from ..paths import resolve_data_dir

CHANNEL_ID = "gemini"

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

CLIENT_ID = os.environ.get(
    "CMDC_PAK_GOOGLE_CLIENT_ID",
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
)
CLIENT_SECRET = os.environ.get("CMDC_PAK_GOOGLE_CLIENT_SECRET", "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")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
]

CALLBACK_PATH = "/oauth-callback"
AUTH_FLOW_TIMEOUT_S = 360
EXPIRY_LEAD_MS = 60_000

ENDPOINT_DAILY = "https://daily-cloudcode-pa.googleapis.com"
ENDPOINT_SANDBOX = "https://daily-cloudcode-pa.sandbox.googleapis.com"
STREAM_PATH = "/v1internal:streamGenerateContent?alt=sse"
LOAD_CODE_ASSIST_PATH = "/v1internal:loadCodeAssist"
LOAD_CODE_ASSIST_BODY = '{"metadata":{"ideType":"ANTIGRAVITY"}}'
DEFAULT_PROJECT = "aicode-consumers"

IDENTITY_HEADERS = {
    "User-Agent": "antigravity/4.3.0 (cmdc-pak)",
    "x-client-name": "antigravity",
    "x-client-version": "4.3.0",
    "x-machine-id": "cmdc-pak",
    "x-vscode-sessionid": "proxy",
}
UPSTREAM_USER_AGENT = "antigravity"

UPSTREAM_FLASH = "gemini-3.8-flash"
CONTEXT_WINDOW = 1_000_000
MAX_OUTPUT_TOKENS = 64_000

EFFORT_IDS = ["low", "medium", "high", "tiered"]
DEFAULT_EFFORT = "medium"
BUDGETS = {"low": 1000, "medium": 4000, "high": 10000, "tiered": -1}

FALLBACK_MODELS = [{"id": UPSTREAM_FLASH, "name": "Gemini 3.8 Flash", "contextWindow": CONTEXT_WINDOW,
                    "maxOutput": MAX_OUTPUT_TOKENS, "vision": True, "reasoning": True}]

IDLE_TIMEOUT_S = 120.0
MAX_IMAGE_BYTES = 10 * 1024 * 1024

SCHEMA_KEYS = {
    "type", "format", "description", "nullable", "enum", "items", "minItems", "maxItems",
    "properties", "required", "minProperties", "maxProperties", "minLength", "maxLength",
    "pattern", "anyOf", "propertyOrdering", "minimum", "maximum",
}

_SIG_FILE = "gemini-sigs.json"
_SIG_MAX = 2000
_SIG_BODY_LIMIT = 512


# ── 工具函数 ────────────────────────────────────────────────────────────────

def sorted_stringify(value: Any) -> str:
    """按键名升序的紧凑 JSON（等价 Go 的 marshalAlphabetical）。"""
    def sort_value(node):
        if isinstance(node, dict):
            return {key: sort_value(node[key]) for key in sorted(node.keys())}
        if isinstance(node, list):
            return [sort_value(item) for item in node]
        return node
    return json.dumps(sort_value(value), separators=(",", ":"), ensure_ascii=False)


def _new_request_id() -> str:
    return f"agent/{int(time.time() * 1000)}/{secrets.token_hex(4)}"


def _fnv1a(text: str) -> str:
    value = 0x811C9DC5
    for byte in text.encode("utf-8"):
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return f"{value:08x}"


def _session_id(project: str, first_text: str) -> str:
    return f"antigravity-{_fnv1a(f'{project}\u0000{first_text}\u0000chat')}"


class SigStore:
    """functionCall 的 thoughtSignature 落盘（键 = 工具名 + 规范化参数）。"""

    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, _SIG_FILE)
        self._entries: dict[str, dict] = {}
        self._latest: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self._entries = {k: v for k, v in data.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            self._entries = {}

    def _flush(self) -> None:
        items = sorted(self._entries.items(), key=lambda kv: kv[1].get("at", 0))[-_SIG_MAX:]
        self._entries = dict(items)
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            temp = f"{self.path}.tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(self._entries, handle, ensure_ascii=False)
            os.replace(temp, self.path)
        except OSError:
            pass

    @staticmethod
    def key(name: str, args_json: str) -> str:
        body = args_json[:_SIG_BODY_LIMIT]
        return hashlib.sha256(f"tool:{name}\u0000{body}".encode("utf-8")).hexdigest()[:16]

    def put(self, name: str, args_json: str, signature: str) -> None:
        key = self.key(name, args_json)
        self._entries[key] = {"sig": signature, "at": int(time.time()), "name": name}
        self._latest[name] = signature
        self._flush()

    def get(self, name: str, args_json: str) -> str | None:
        entry = self._entries.get(self.key(name, args_json))
        if entry and isinstance(entry.get("sig"), str):
            return entry["sig"]
        return self._latest.get(name)


# ── OAuth ───────────────────────────────────────────────────────────────────

def build_auth_url(redirect_uri: str, state: str) -> str:
    params = {
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": redirect_uri,
        "scope": " ".join(SCOPES), "state": state, "access_type": "offline",
        "include_granted_scopes": "true", "prompt": "consent",
    }
    return f"{AUTH_ENDPOINT}?{'&'.join(f'{quote(k)}={quote(v)}' for k, v in params.items())}"


async def _token_request(form: dict) -> dict:
    client = await get_client()
    response = await client.post(TOKEN_ENDPOINT, data=form,
                                 headers={"content-type": "application/x-www-form-urlencoded"},
                                 timeout=30)
    payload = response.json() if response.content else {}
    if response.status_code >= 400 or payload.get("error"):
        raise UpstreamError(f"gemini token request failed: {payload.get('error_description') or payload.get('error') or response.status_code}",
                            CODE["credential"], status=response.status_code)
    return payload


def credential_from_grant(grant: dict, previous: dict | None = None) -> dict:
    credential = {
        "access_token": grant.get("access_token", ""),
        "token_type": grant.get("token_type", "Bearer"),
        "scope": grant.get("scope", " ".join(SCOPES)),
        "expires_in": grant.get("expires_in", 3600),
        "expiry": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + int(grant.get("expires_in") or 3600))),
        "refresh_token": grant.get("refresh_token") or (previous or {}).get("refresh_token"),
    }
    for key in ("cloudaicompanionProject", "sub", "email"):
        if (previous or {}).get(key):
            credential[key] = previous[key]
    identity = _identity_from_id_token(grant.get("id_token"))
    credential.update({k: v for k, v in identity.items() if v})
    return credential


def _identity_from_id_token(token: Any) -> dict:
    if not isinstance(token, str) or token.count(".") != 2:
        return {}
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return {"sub": data.get("sub", ""), "email": data.get("email", "")}
    except Exception:  # noqa: BLE001
        return {}


def is_expired(credential: dict) -> bool:
    expiry = credential.get("expiry")
    if not isinstance(expiry, str):
        return False
    try:
        stamp = time.mktime(time.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    except ValueError:
        return False
    return stamp * 1000 - EXPIRY_LEAD_MS <= time.time() * 1000


async def refresh_credential(credential: dict) -> dict:
    refresh_token = credential.get("refresh_token")
    if not refresh_token:
        raise UpstreamError("gemini credential cannot be refreshed (no refresh_token)", CODE["credential"])
    try:
        grant = await _token_request({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                                      "refresh_token": refresh_token, "grant_type": "refresh_token"})
    except UpstreamError as error:
        if re.search(r"invalid_grant|invalid_client|expired|revoked|unauthorized", error.message, re.IGNORECASE):
            raise UpstreamError("gemini refresh token expired; please sign in again", CODE["credential"])
        raise
    return credential_from_grant(grant, credential)


async def run_login(*, open_browser: bool = True, timeout_s: int = AUTH_FLOW_TIMEOUT_S) -> dict:
    """完整 OAuth 浏览器登录，返回凭据 dict。"""
    state = secrets.token_hex(16)
    result: dict[str, Any] = {}
    done = asyncio.Event()

    async def handle(reader, writer):
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            _, target, _ = (request_line.split(" ") + ["", "", ""])[:3]
            query = dict(pair.split("=", 1) for pair in urlsplit(target).query.split("&") if "=" in pair)
            ok = query.get("state") == state and bool(query.get("code"))
            result["code"] = query.get("code") if ok else None
            body = b"<h1>OK</h1>" if ok else b"<h1>state mismatch</h1>"
            writer.write(f"HTTP/1.1 {'200 OK' if ok else '400 Bad Request'}\r\n"
                         f"Content-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                         + body)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            done.set()

    import contextlib  # noqa: F401  (handler 闭包在下方使用)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    redirect_uri = f"http://localhost:{port}{CALLBACK_PATH}"
    if open_browser:
        _open_external(build_auth_url(redirect_uri, state))
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        raise UpstreamError("gemini login timed out waiting for the browser callback", CODE["timeout"])
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()
    code = result.get("code")
    if not code:
        raise UpstreamError("gemini login callback carried no valid code", CODE["credential"])
    grant = await _token_request({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code,
                                  "grant_type": "authorization_code", "redirect_uri": redirect_uri})
    credential = credential_from_grant(grant)
    with contextlib.suppress(Exception):
        client = await get_client()
        info = await client.get(USERINFO_ENDPOINT, headers={"authorization": f"Bearer {credential['access_token']}"}, timeout=15)
        if info.status_code < 400:
            data = info.json()
            credential.setdefault("email", data.get("email", ""))
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


# ── 目录 / project ──────────────────────────────────────────────────────────

def _headers(credential: dict, *, include_accept: bool = False) -> dict[str, str]:
    headers = {**IDENTITY_HEADERS, "Authorization": f"Bearer {credential.get('access_token', '')}",
               "Content-Type": "application/json"}
    if include_accept:
        headers["Accept"] = "application/json"
    return headers


async def fetch_models(credential: dict) -> dict:
    # Cloud Code 没有对外模型列表端点；模型表是静态的（与原版一致）。
    return {"models": [dict(m) for m in FALLBACK_MODELS]}


async def resolve_project(credential: dict) -> str:
    """探测 Cloud Code 项目号；探测失败返回空串（调用方据此不发推理）。"""
    if credential.get("cloudaicompanionProject"):
        return credential["cloudaicompanionProject"]
    client = await get_client()
    for endpoint in (ENDPOINT_SANDBOX, ENDPOINT_DAILY):
        try:
            response = await client.post(f"{endpoint}{LOAD_CODE_ASSIST_PATH}",
                                         headers=_headers(credential), content=LOAD_CODE_ASSIST_BODY, timeout=30)
            if response.status_code >= 400:
                continue
            data = response.json()
            project = data.get("cloudaicompanionProject") or (data.get("currentTier") or {}).get("cloudaicompanionProject")
            return project if isinstance(project, str) and project else DEFAULT_PROJECT
        except Exception:  # noqa: BLE001
            continue
    return ""


# ── 请求体翻译 ──────────────────────────────────────────────────────────────

def _sanitize_schema(schema: Any) -> Any:
    if not isinstance(schema, dict):
        return {"type": "object"}
    out = {}
    for key, value in schema.items():
        if key not in SCHEMA_KEYS:
            continue
        if key == "properties" and isinstance(value, dict):
            out[key] = {k: _sanitize_schema(v) for k, v in value.items()}
        elif key == "items":
            out[key] = _sanitize_schema(value)
        elif key == "type" and isinstance(value, list):
            out[key] = next((v for v in value if v != "null"), "string")
            out["nullable"] = True
        elif key == "enum" and isinstance(value, list) and all(isinstance(v, str) for v in value):
            out[key] = value
        elif key in ("description", "format", "pattern"):
            out[key] = str(value)
        elif key in ("required",) and isinstance(value, list):
            out[key] = [str(v) for v in value]
        elif isinstance(value, (int, float, str, bool)):
            out[key] = value
    if "type" not in out and "properties" in out:
        out["type"] = "object"
    return out


def _tier_of(body: dict) -> str:
    effort = body.get("reasoning_effort")
    if isinstance(effort, str) and effort in EFFORT_IDS:
        return effort
    return DEFAULT_EFFORT


def _canonical_args(args: Any) -> str:
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except ValueError:
            return "{}"
    return sorted_stringify(args if isinstance(args, dict) else {})


def _image_part(url: str):
    match = re.match(r"data:([^;,]+);base64,(.*)$", url, re.DOTALL)
    if not match:
        return None
    media, data = match.group(1), re.sub(r"[\s]", "", match.group(2))
    if len(data) * 3 // 4 > MAX_IMAGE_BYTES:
        raise UpstreamError("gemini: image exceeds the 10MB inline limit", CODE["client"])
    return {"inlineData": {"mimeType": media or "image/png", "data": data}}


def translate_request(body: dict, project: str, sig_store: SigStore, tier: str) -> dict:
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    tool_names: dict[str, str] = {}
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "assistant":
            for call in message.get("tool_calls") or []:
                if isinstance(call, dict) and call.get("id"):
                    tool_names[call["id"]] = (call.get("function") or {}).get("name", "")

    contents: list[dict] = []
    system_parts: list[dict] = []
    first_text = ""

    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        raw = message.get("content")
        if role in ("system", "developer"):
            text = raw if isinstance(raw, str) else " ".join(
                p.get("text", "") for p in raw if isinstance(p, dict) and isinstance(p.get("text"), str)) if isinstance(raw, list) else ""
            if text:
                system_parts.append({"text": text})
            continue
        parts: list[dict] = []
        if role == "tool":
            name = tool_names.get(message.get("tool_call_id", ""), "")
            if not name:
                continue
            text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
            parts.append({"functionResponse": {"name": name, "response": {"content": text or "(no output)"}}})
        elif role == "assistant":
            if isinstance(raw, str) and raw:
                parts.append({"text": raw})
            for call in message.get("tool_calls") or []:
                fn = call.get("function") or {}
                name = fn.get("name", "")
                if not name:
                    continue
                args_json = _canonical_args(fn.get("arguments"))
                part = {"functionCall": {"name": name, "args": json.loads(args_json) if args_json else {}}}
                signature = sig_store.get(name, args_json)
                if signature:
                    part["thoughtSignature"] = signature
                parts.append(part)
        else:
            if isinstance(raw, str):
                if raw:
                    parts.append({"text": raw})
                    first_text = first_text or raw
            elif isinstance(raw, list):
                for part in raw:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") in ("text", "input_text") and part.get("text"):
                        parts.append({"text": part["text"]})
                        first_text = first_text or part["text"]
                    elif part.get("type") == "image_url":
                        url = part.get("image_url")
                        url = url.get("url") if isinstance(url, dict) else url
                        if isinstance(url, str):
                            image = _image_part(url)
                            if image:
                                parts.append(image)
        if parts:
            contents.append({"role": "model" if role == "assistant" else "user", "parts": parts})

    if not contents:
        raise UpstreamError("gemini: messages 里没有可用内容", CODE["client"])

    request: dict[str, Any] = {"contents": contents, "sessionId": _session_id(project, first_text)}
    generation: dict[str, Any] = {"maxOutputTokens": int(body.get("max_tokens") or MAX_OUTPUT_TOKENS),
                                  "thinkingConfig": {"includeThoughts": True}}
    budget = BUDGETS.get(tier, BUDGETS[DEFAULT_EFFORT])
    if budget >= 0:
        generation["thinkingConfig"]["thinkingBudget"] = budget
    if isinstance(body.get("temperature"), (int, float)):
        generation["temperature"] = body["temperature"]
    request["generationConfig"] = generation
    if system_parts:
        request["systemInstruction"] = {"role": "system", "parts": system_parts}

    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        declarations = []
        for tool in tools:
            fn = tool.get("function") if isinstance(tool, dict) and isinstance(tool.get("function"), dict) else tool
            name = (fn or {}).get("name")
            if not isinstance(name, str) or not name:
                continue
            declarations.append({"name": name, "description": str(fn.get("description") or ""),
                                 "parameters": _sanitize_schema(fn.get("parameters"))})
        if declarations:
            request["tools"] = [{"functionDeclarations": declarations}]
            request["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}

    return {"model": f"{UPSTREAM_FLASH}-{tier}", "project": project, "request": request,
            "requestId": _new_request_id(), "userAgent": UPSTREAM_USER_AGENT}


# ── 流式响应 ────────────────────────────────────────────────────────────────

def _map_usage(usage: Any) -> dict | None:
    if not isinstance(usage, dict):
        return None
    prompt = usage.get("promptTokenCount") or 0
    cached = usage.get("cachedContentTokenCount") or 0
    output = usage.get("candidatesTokenCount") or 0
    out = {"inputTokens": max(0, prompt - cached), "outputTokens": output,
           "totalTokens": usage.get("totalTokenCount") or (prompt + output)}
    if cached:
        out["cacheReadTokens"] = cached
    thoughts = usage.get("thoughtsTokenCount") or 0
    if thoughts:
        out["reasoningTokens"] = thoughts
    return out


def _map_finish(reason: Any, tool_calls: int) -> dict:
    if tool_calls > 0:
        return {"kind": "tool-calls"}
    if reason == "MAX_TOKENS":
        return {"kind": "max-tokens"}
    return {"kind": "stop"}


_sig_store: SigStore | None = None


def _store() -> SigStore:
    global _sig_store
    if _sig_store is None:
        _sig_store = SigStore(str(resolve_data_dir()))
    return _sig_store


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    sig_store = _store()
    tier = _tier_of(body)

    project = await resolve_project(credential)
    if not project:
        raise UpstreamError("gemini: 无法确定 Cloud Code 项目号", CODE["server"])
    payload = translate_request(body, project, sig_store, tier)

    if is_expired(credential):
        credential = await refresh_credential(credential)
        if on_refresh is not None:
            on_refresh(credential)

    client = await get_client()
    endpoint_index = 0
    dropped_signatures = False
    for _ in range(3):
        url = (ENDPOINT_SANDBOX if endpoint_index == 0 else ENDPOINT_DAILY) + STREAM_PATH
        try:
            async with client.stream("POST", url, headers=_headers(credential, include_accept=False),
                                     content=sorted_stringify(payload),
                                     timeout=httpx.Timeout(connect=15.0, read=IDLE_TIMEOUT_S, write=60.0, pool=15.0)) as response:
                if response.status_code == 401:
                    credential = await refresh_credential(credential)
                    if on_refresh is not None:
                        on_refresh(credential)
                    endpoint_index = 1
                    continue
                if response.status_code >= 400:
                    text = (await response.aread()).decode("utf-8", "replace")[:300]
                    if re.search(r"signature", text, re.IGNORECASE) and not dropped_signatures:
                        dropped_signatures = True
                        _strip_signatures(payload)
                        continue
                    if response.status_code in (403, 404):
                        endpoint_index = 1 - endpoint_index
                        continue
                    raise UpstreamError(f"gemini: HTTP {response.status_code} {text}", CODE["server"],
                                        status=response.status_code)
                async for chunk in _consume(response.aiter_lines(), sig_store):
                    yield chunk
                return
        except UpstreamError:
            raise
        except httpx.HTTPError as error:
            raise UpstreamError(f"gemini: request failed: {error}", CODE["transport"])
    raise UpstreamError("gemini: 所有端点与账号均不可用", CODE["quota"])


def _strip_signatures(payload: dict) -> None:
    for content in payload.get("request", {}).get("contents", []):
        for part in content.get("parts", []):
            part.pop("thoughtSignature", None)


async def _consume(lines: AsyncIterator[str], sig_store: SigStore) -> AsyncIterator[dict]:
    index = 0
    tool_calls = 0
    saw_any = False
    usage_best = None
    finish_reason = None
    async for line in lines:
        line = line.strip()
        if not line or line.startswith(":") or line.startswith("event:"):
            continue
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if raw in ("", "[DONE]"):
            continue
        try:
            frame = json.loads(raw)
        except ValueError:
            continue
        response = frame.get("response") if isinstance(frame, dict) and "response" in frame else frame
        if not isinstance(response, dict):
            continue
        usage = _map_usage(response.get("usageMetadata"))
        if usage is not None:
            usage_best = usage if usage_best is None else {k: max(usage_best.get(k, 0), v) for k, v in usage.items()}
        for candidate in response.get("candidates") or []:
            for part in (candidate.get("content") or {}).get("parts") or []:
                if not isinstance(part, dict):
                    continue
                call = part.get("functionCall")
                if isinstance(call, dict):
                    saw_any = True
                    name = call.get("name", "")
                    args_json = sorted_stringify(call.get("args") or {})
                    signature = part.get("thoughtSignature")
                    if isinstance(signature, str) and signature:
                        sig_store.put(name, args_json, signature)
                    call_id = f"gemini_tool_{int(time.time() * 1000):x}_{index}"
                    yield {"type": "block-start", "index": index, "blockType": "tool-call"}
                    yield {"type": "tool-call-delta", "index": index, "id": call_id, "name": name,
                           "argumentsDelta": args_json}
                    yield {"type": "block-end", "index": index,
                           "block": {"type": "tool-call", "id": call_id, "name": name, "arguments": args_json}}
                    index += 1
                    tool_calls += 1
                    continue
                text_value = part.get("text")
                if isinstance(text_value, str) and text_value:
                    saw_any = True
                    if part.get("thought") is True:
                        yield {"type": "reasoning-delta", "index": index, "text": text_value}
                    else:
                        yield {"type": "text-delta", "index": index, "text": text_value}
            reason = candidate.get("finishReason")
            if isinstance(reason, str) and reason:
                finish_reason = reason
    if not saw_any:
        raise UpstreamError("gemini: 模型未返回任何内容块", CODE["empty"])
    if usage_best is not None:
        yield {"type": "usage", "usage": usage_best}
    yield {"type": "finish", "reason": _map_finish(finish_reason, tool_calls)}
