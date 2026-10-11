"""免费车道的上游线格式（OpenCode Zen 网关）。

本模块的每个事实都来自原版对真实网关的直接请求核对：
公开免密凭据、客户端指纹头、按模型分流的端点、免费层工具指纹闸门
（缺少四件套会 403 FreeTierError）、按会话计的额度、地区门（403 RegionError）。
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time

UPSTREAM_BASE = os.environ.get("OUR_FREE_MODEL_BASE", "https://opencode.ai").rstrip("/")

# 网关要求 User-Agent 携带 >= 1.17 的 opencode/<version> 记号。
CLIENT_UA = "opencode/1.18.31"
MAX_SESSION_LENGTH = 256
MAX_TOOL_NAME_LEN = 128
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# 免费层要求声明的四件套（小写）。
FINGERPRINT_TOOLS = ["bash", "glob", "grep", "read"]

# 可由调用方已有工具顶替的槽位。
QUARTET_DONORS = {"bash": ["pwsh"]}

# 走 /responses 而不是 /chat/completions 的模型。
RESPONSES_MODELS = {"muse-spark-1.2-contributor-free", "muse-spark-1.3-contributor-free"}
# 走 Anthropic 形状 /messages 的模型。
MESSAGES_MODELS = {"union-alpha"}

SESSION_RE = re.compile(r"^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$")
REQUEST_RE = re.compile(r"^msg_[0-9a-f]{12}[0-9A-Za-z]{14}$")

ANTHROPIC_API_VERSION = "2023-06-01"

_last_stamp = 0
_seq = 0


def _base62_from(data: bytes) -> str:
    return "".join(BASE62[b % 62] for b in data)


def mint_session_id(timestamp: int | None = None) -> str:
    """铸造网关形状的规范会话 id（时间前缀 + 单调计数）。"""
    global _last_stamp, _seq
    ts = int(time.time() * 1000) if timestamp is None else timestamp
    if ts != _last_stamp:
        _last_stamp = ts
        _seq = 0
    _seq += 1
    value = ~((ts << 12) + _seq)
    value &= (1 << 48) - 1
    hex_part = "".join(f"{(value >> (40 - 8 * i)) & 0xFF:02x}" for i in range(6))
    return f"ses_{hex_part}{_base62_from(secrets.token_bytes(14))}"


def mint_request_id(timestamp: int | None = None) -> str:
    """为单轮铸造网关形状的请求 id。"""
    ts = int(time.time() * 1000) if timestamp is None else timestamp
    value = (ts << 12) + 1
    hex_part = "".join(f"{(value >> (40 - 8 * i)) & 0xFF:02x}" for i in range(6))
    return f"msg_{hex_part}{_base62_from(secrets.token_bytes(14))}"


def session_for_conversation(session_id: str | None) -> str:
    """把下游会话稳定映射到同一个上游会话（免费层按会话计额）。"""
    if isinstance(session_id, str) and SESSION_RE.match(session_id.strip()):
        return session_id.strip()
    seed = session_id.strip() if isinstance(session_id, str) and session_id.strip() else "global"
    digest = hashlib.sha256(f"our-free-model\0{seed}".encode("utf-8")).digest()
    return f"ses_{digest[:6].hex()}{_base62_from(digest[6:20])}"


def request_id_for(session_id: str, turn_seed: str | None) -> str:
    """稳定的每轮请求 id：同一轮的重试共用它。"""
    if not isinstance(turn_seed, str) or turn_seed == "":
        return mint_request_id()
    digest = hashlib.sha256(f"our-free-model-req\0{session_id}\0{turn_seed}".encode("utf-8")).digest()
    value = f"msg_{digest[:6].hex()}{_base62_from(digest[6:20])}"
    return value if REQUEST_RE.match(value) else mint_request_id()


def base_model_id(model: str | None) -> str:
    """去掉尾部的 ``(level)`` 思考后缀，让查询命中基础 id。"""
    return re.sub(r"\([^()]+\)\s*$", "", str(model or "")).strip()


def _is_muse_spark(model_id: str | None) -> bool:
    clean = base_model_id(model_id)
    base = clean.split("/")[-1] if "/" in clean else clean
    return re.match(r"^muse[-_]?spark(?:$|[-_:.\s])", base, re.IGNORECASE) is not None


def is_responses_model(model_id: str | None) -> bool:
    return base_model_id(model_id) in RESPONSES_MODELS or _is_muse_spark(model_id)


def is_messages_model(model_id: str | None) -> bool:
    return base_model_id(model_id) in MESSAGES_MODELS


def endpoint_for(model_id: str | None) -> str:
    """该模型由哪个上游路径服务。"""
    if is_responses_model(model_id):
        return "/zen/v1/responses"
    if is_messages_model(model_id):
        return "/zen/v1/messages"
    return "/zen/v1/chat/completions"


def wire_for(model_id: str | None) -> str:
    """该端点说的是哪种线格式。"""
    path = endpoint_for(model_id)
    if path == "/zen/v1/responses":
        return "responses"
    if path == "/zen/v1/messages":
        return "messages"
    return "chat"


def gateway_headers(session: str, request_id: str, stream: bool, accept: str | None = None) -> dict[str, str]:
    """网关据以识别真实桌面客户端的请求头。``Bearer public`` 是池化免密凭据。"""
    return {
        "content-type": "application/json",
        "authorization": "Bearer public",
        "user-agent": CLIENT_UA,
        "x-opencode-client": "desktop",
        "x-opencode-session": session,
        "x-opencode-request": request_id,
        "x-opencode-project": "global",
        "accept": accept if accept is not None else ("text/event-stream" if stream else "*/*"),
    }


def _tool_name_of(tool) -> str:
    if not isinstance(tool, dict):
        return ""
    name = tool.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    fn = tool.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
        return fn["name"].strip()
    return ""


def _quartet_key(name) -> str:
    lower = str(name or "").strip().lower()
    return lower if lower in FINGERPRINT_TOOLS else ""


def _function_of(tool):
    fn = tool.get("function") if isinstance(tool, dict) else None
    return fn if isinstance(fn, dict) else None


def apply_fingerprint(body: dict, style: bool | str) -> dict[str, str]:
    """满足免费层的工具指纹闸门。

    @param body: 请求体，就地修改
    @param style: True 为 Responses，False 为 Chat，'claude' 为 Messages
    @returns: {发出的拼写 -> 调用方的拼写}
    """
    flat = style is True
    claude = style == "claude"
    rename: dict[str, str] = {}
    tools = body.get("tools") if isinstance(body.get("tools"), list) else []
    had_client_tools = len(tools) > 0
    seen: set[str] = set()
    out: list = []

    for tool in tools:
        current = _tool_name_of(tool)
        key = _quartet_key(current)
        if not key:
            out.append(tool)
            continue
        if key in seen:
            continue
        seen.add(key)
        if current != key:
            rename[key] = current
            fn = _function_of(tool)
            if fn is not None:
                out.append({**tool, "function": {**fn, "name": key}})
            else:
                out.append({**tool, "name": key})
        else:
            out.append(tool)

    promoted: set[str] = set()
    for name in FINGERPRINT_TOOLS:
        if name in seen:
            continue
        donors = QUARTET_DONORS.get(name, [])
        index = -1
        for i, tool in enumerate(out):
            original = _tool_name_of(tool)
            if original == "" or _quartet_key(original) != "":
                continue
            lower = original.lower()
            if lower not in promoted and lower in donors:
                index = i
                break
        if index == -1:
            continue
        tool = out[index]
        original = _tool_name_of(tool)
        promoted.add(original.lower())
        rename[name] = original
        fn = _function_of(tool)
        out[index] = {**tool, "function": {**fn, "name": name}} if fn is not None else {**tool, "name": name}
        seen.add(name)

    for name in FINGERPRINT_TOOLS:
        if name in seen:
            continue
        desc = "This tool is currently unavailable and must not be used."
        if claude:
            out.append({"name": name, "description": desc, "input_schema": {"type": "object", "properties": {}}})
        elif flat:
            out.append({"type": "function", "name": name, "description": desc, "parameters": {"type": "object", "properties": {}}})
        else:
            out.append({"type": "function", "function": {"name": name, "description": desc, "parameters": {"type": "object", "properties": {}}}})

    body["tools"] = out
    if not body.get("tool_choice"):
        if flat:
            body["tool_choice"] = "auto"
        elif not had_client_tools:
            body["tool_choice"] = {"type": "none"} if claude else "none"
    return rename


def restore_tool_name(name: str, rename: dict[str, str] | None) -> str:
    if not rename:
        return name
    return rename.get(name, name)


def declared_tool_names(body: dict) -> set[str]:
    names: set[str] = set()
    tools = body.get("tools") if isinstance(body.get("tools"), list) else []
    for tool in tools:
        n = _tool_name_of(tool)
        if n:
            names.add(n)
    return names


def truncate_session(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    trimmed = value.strip()
    return trimmed[:MAX_SESSION_LENGTH] if len(trimmed) > MAX_SESSION_LENGTH else trimmed
