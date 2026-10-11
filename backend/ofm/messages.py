"""内部消息词汇 ↔ 上游三种线格式，外加工具调用配对修复。

免费车道不是单一 API：``chat``（OpenAI Chat Completions）、
``responses``（OpenAI Responses）、``messages``（Anthropic Messages）。
哪个模型走哪种由 ``upstream.endpoint_for`` 决定。
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .upstream import MAX_TOOL_NAME_LEN

IMAGE_MEDIA = {"image/png", "image/jpeg", "image/webp", "image/gif"}


def text_of(blocks) -> str:
    parts = []
    for block in blocks or []:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "\n".join(parts)


def blocks_of(content) -> list:
    if isinstance(content, str):
        return [] if content == "" else [{"type": "text", "text": content}]
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, str):
                out.append({"type": "text", "text": part})
            elif isinstance(part, dict) and part.get("type") in ("text", "input_text", "output_text"):
                out.append({"type": "text", "text": str(part.get("text", ""))})
            elif isinstance(part, dict):
                out.append(part)
        return out
    return []


def has_blocks(blocks, block_type: str) -> bool:
    return isinstance(blocks, list) and any(isinstance(b, dict) and b.get("type") == block_type for b in blocks)


def image_data_url(block: dict, resolve_image: Callable | None) -> str | None:
    if block.get("offloaded") is True:
        return None
    if resolve_image is not None:
        resolved = resolve_image(block.get("attachment"))
        if resolved is not None:
            return resolved
    attachment = block.get("attachment") or {}
    return attachment.get("url") if isinstance(attachment.get("url"), str) else None


def tool_results_of(message: dict) -> list[dict]:
    if message.get("role") == "tool":
        call_id = _call_id_of(message)
        if call_id is None:
            return []
        return [{"callId": call_id, "content": blocks_of(message.get("content")), "isError": message.get("isError") is True}]
    out = []
    for block in blocks_of(message.get("content")):
        if not isinstance(block, dict) or block.get("type") != "tool-result":
            continue
        call_id = str(block.get("toolCallId", (message.get("source") or {}).get("callId", "")))
        if call_id == "":
            continue
        out.append({"callId": call_id, "content": blocks_of(block.get("content")), "isError": block.get("isError") is True})
    return out


def _call_id_of(message: dict) -> str | None:
    cid = str(message.get("toolCallId", (message.get("source") or {}).get("callId", "")))
    return None if cid == "" else cid


def repair_tool_pairing(messages: list[dict]) -> list[dict]:
    """丢弃从未被回答的工具调用，以及没有调用可回答的结果。"""
    lst = messages or []
    answered = set()
    for message in lst:
        for result in tool_results_of(message):
            answered.add(result["callId"])

    kept_calls: set[str] = set()
    out: list[dict] = []
    for message in lst:
        results = tool_results_of(message)
        if results:
            if message.get("role") == "tool":
                if results[0]["callId"] in kept_calls:
                    out.append(message)
                continue
            kept = {r["callId"] for r in results if r["callId"] in kept_calls}
            blocks = blocks_of(message.get("content"))
            rest = [b for b in blocks if not (isinstance(b, dict) and b.get("type") == "tool-result")
                    or str(b.get("toolCallId", (message.get("source") or {}).get("callId", ""))) in kept]
            if len(rest) == len(blocks):
                out.append(message)
            elif rest:
                out.append({**message, "content": rest})
            continue
        if message.get("role") == "tool":
            continue
        if message.get("role") != "assistant":
            out.append(message)
            continue
        blocks = blocks_of(message.get("content"))
        tool_blocks = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool-call"]
        calls = [b for b in tool_blocks if str(b.get("id", "")) in answered and str(b.get("name", "")) != ""]
        for call in calls:
            kept_calls.add(str(call.get("id")))
        if len(calls) == len(tool_blocks):
            if calls or any(isinstance(b, dict) and b.get("type") == "text" and b.get("text") for b in blocks):
                out.append(message)
            continue
        if not calls:
            if any(isinstance(b, dict) and b.get("type") == "text" and b.get("text") for b in blocks):
                out.append({**message, "content": [b for b in blocks if not (isinstance(b, dict) and b.get("type") == "tool-call")]})
            continue
        out.append({**message, "content": [b for b in blocks if not (isinstance(b, dict) and b.get("type") == "tool-call") or b in calls]})
    return out


def to_chat_messages(messages: list[dict], resolve_image, warnings: list | None) -> list[dict]:
    out: list[dict] = []
    follow_up: list = []

    def flush_follow_up():
        if follow_up:
            out.append({"role": "user", "content": follow_up[:]})
            follow_up.clear()

    for message in messages or []:
        results = tool_results_of(message)
        if not results:
            flush_follow_up()
        blocks = blocks_of(message.get("content"))
        if results:
            for result in results:
                images = []
                for block in result["content"]:
                    if isinstance(block, dict) and block.get("type") == "image":
                        url = image_data_url(block, resolve_image)
                        if url is not None:
                            images.append({"type": "image_url", "image_url": {"url": url}})
                        elif warnings is not None:
                            warnings.append("image-dropped")
                text = text_of(result["content"])
                out.append({"role": "tool", "tool_call_id": result["callId"],
                            "content": text or ("(see attached image)" if images else "(no output)")})
                if images:
                    follow_up.append({"type": "text", "text": f"The result of tool call {result['callId']} is {len(images)} image(s), attached below."})
                    follow_up.extend(images)
            blocks = [b for b in blocks if not (isinstance(b, dict) and b.get("type") == "tool-result")]
        role = message.get("role")
        if role in ("system", "developer"):
            text = text_of(blocks)
            if text:
                out.append({"role": "system", "content": text})
        elif role == "user":
            parts = []
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                    parts.append({"type": "text", "text": block["text"]})
                elif isinstance(block, dict) and block.get("type") == "image":
                    url = image_data_url(block, resolve_image)
                    if url is not None:
                        parts.append({"type": "image_url", "image_url": {"url": url}})
                    elif warnings is not None:
                        warnings.append("image-dropped")
            if not parts:
                fallback = text_of(blocks)
                if fallback:
                    out.append({"role": "user", "content": fallback})
                continue
            if results:
                follow_up.extend(parts)
            else:
                out.append({"role": "user", "content": parts[0]["text"] if len(parts) == 1 and parts[0]["type"] == "text" else parts})
        elif role == "assistant":
            text = text_of(blocks)
            calls = []
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "tool-call":
                    calls.append({"id": str(block.get("id", "")), "type": "function",
                                  "function": {"name": str(block.get("name", "")),
                                               "arguments": block["arguments"] if isinstance(block.get("arguments"), str) else "{}"}})
            if not text and not calls:
                continue
            entry: dict[str, Any] = {"role": "assistant", "content": text or None}
            if calls:
                entry["tool_calls"] = calls
            out.append(entry)
    flush_follow_up()
    return out


def claude_image_block(url: str | None, warnings: list | None):
    if url is None:
        if warnings is not None:
            warnings.append("image-dropped")
        return None
    comma = str(url).find(",")
    head = "" if comma == -1 else str(url)[:comma]
    import re
    match = re.search(r"data:([^;]+)", head)
    media = match.group(1) if match else None
    if media is None or media not in IMAGE_MEDIA:
        if warnings is not None:
            warnings.append("image-dropped")
        return None
    return {"type": "image", "source": {"type": "base64", "media_type": media, "data": str(url)[comma + 1:]}}


def to_claude_messages(messages: list[dict], resolve_image, warnings: list | None) -> dict:
    out: list[dict] = []
    system_text = ""

    def push(role: str, blocks: list) -> None:
        if out and out[-1]["role"] == role:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": role, "content": list(blocks)})

    for message in messages or []:
        results = tool_results_of(message)
        if message.get("role") in ("system", "developer"):
            text = text_of(blocks_of(message.get("content")))
            if text:
                system_text = f"{system_text}\n\n{text}" if system_text else text
            continue
        if results:
            lead = []
            for result in results:
                inner = []
                for block in result["content"]:
                    if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                        inner.append({"type": "text", "text": block["text"]})
                    elif isinstance(block, dict) and block.get("type") == "image":
                        image = claude_image_block(image_data_url(block, resolve_image), warnings)
                        if image is not None:
                            inner.append(image)
                lead.append({"type": "tool_result", "tool_use_id": result["callId"],
                             "content": inner or [{"type": "text", "text": "(no output)"}],
                             "is_error": result["isError"]})
            push("user", lead)
            if message.get("role") == "tool":
                continue
        blocks = [b for b in blocks_of(message.get("content")) if not (isinstance(b, dict) and b.get("type") == "tool-result")]
        content = []
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                content.append({"type": "text", "text": block["text"]})
            elif isinstance(block, dict) and block.get("type") == "tool-call":
                try:
                    inp = json.loads(block.get("arguments") or "{}")
                except ValueError:
                    inp = {}
                content.append({"type": "tool_use", "id": str(block.get("id", "")), "name": str(block.get("name", "")), "input": inp})
            elif isinstance(block, dict) and block.get("type") == "image":
                image = claude_image_block(image_data_url(block, resolve_image), warnings)
                if image is not None:
                    content.append(image)
        if not content:
            continue
        push("assistant" if message.get("role") == "assistant" else "user", content)
    return {"system": system_text or None, "messages": out}


def to_response_input(messages: list[dict], resolve_image, warnings: list | None) -> list[dict]:
    out: list[dict] = []
    follow_up: list = []

    def flush_follow_up():
        if follow_up:
            out.append({"type": "message", "role": "user", "content": follow_up[:]})
            follow_up.clear()

    for message in messages or []:
        results = tool_results_of(message)
        if not results:
            flush_follow_up()
        if results:
            for result in results:
                images = []
                for block in result["content"]:
                    if isinstance(block, dict) and block.get("type") == "image":
                        url = image_data_url(block, resolve_image)
                        if url is not None:
                            images.append({"type": "input_image", "image_url": url})
                        elif warnings is not None:
                            warnings.append("image-dropped")
                text = text_of(result["content"])
                out.append({"type": "function_call_output", "call_id": result["callId"],
                            "output": text or ("(see attached image)" if images else "(no output)")})
                if images:
                    follow_up.append({"type": "input_text", "text": f"The result of tool call {result['callId']} is {len(images)} image(s), attached below."})
                    follow_up.extend(images)
        if message.get("role") == "tool":
            continue
        blocks = [b for b in blocks_of(message.get("content")) if not (isinstance(b, dict) and b.get("type") == "tool-result")]
        if message.get("role") in ("system", "developer"):
            text = text_of(blocks)
            if text:
                out.append({"type": "message", "role": "system", "content": [{"type": "input_text", "text": text}]})
            continue
        if message.get("role") == "assistant":
            text = text_of(blocks)
            if text:
                out.append({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]})
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "tool-call":
                    out.append({"type": "function_call", "call_id": str(block.get("id", "")),
                                "name": str(block.get("name", "")),
                                "arguments": block["arguments"] if isinstance(block.get("arguments"), str) else "{}"})
            continue
        parts = []
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                parts.append({"type": "input_text", "text": block["text"]})
            elif isinstance(block, dict) and block.get("type") == "image":
                url = image_data_url(block, resolve_image)
                if url is not None:
                    parts.append({"type": "input_image", "image_url": url})
                elif warnings is not None:
                    warnings.append("image-dropped")
        if parts:
            if results:
                follow_up.extend(parts)
            else:
                out.append({"type": "message", "role": "user", "content": parts})
    flush_follow_up()
    return out


def to_tool_defs(tools, style: str) -> list[dict]:
    lst = []
    for tool in tools or []:
        fn = tool.get("function") if isinstance(tool, dict) and isinstance(tool.get("function"), dict) else tool
        name = str((fn or {}).get("name", "")).strip()
        if not name:
            continue
        parameters = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {"type": "object", "properties": {}}
        description = fn.get("description") if isinstance(fn.get("description"), str) else ""
        if style == "claude":
            lst.append({"name": name[:MAX_TOOL_NAME_LEN], "description": description, "input_schema": parameters})
        elif style == "flat":
            lst.append({"type": "function", "name": name[:MAX_TOOL_NAME_LEN], "description": description, "parameters": parameters})
        else:
            lst.append({"type": "function", "function": {"name": name[:MAX_TOOL_NAME_LEN], "description": description, "parameters": parameters}})
    return lst


def needs_vision(messages: list[dict]) -> bool:
    return any(has_blocks(m.get("content"), "image") and
               any(isinstance(b, dict) and b.get("type") == "image" and b.get("offloaded") is not True for b in m.get("content") or [])
               for m in messages or [])
