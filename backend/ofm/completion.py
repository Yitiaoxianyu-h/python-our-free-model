"""OpenAI 兼容入口到内部链路的桥接：请求投影、结果折叠、用量换算。"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from .adapter import ROUTE_MAIN
from .logs import preview


def to_openai_usage(usage: dict | None):
    if usage is None:
        return None
    return {
        "prompt_tokens": (usage.get("inputTokens") or 0) + (usage.get("cacheReadTokens") or 0),
        "completion_tokens": usage.get("outputTokens") or 0,
        "total_tokens": (usage.get("inputTokens") or 0) + (usage.get("cacheReadTokens") or 0) + (usage.get("outputTokens") or 0),
        "prompt_tokens_details": {"cached_tokens": usage.get("cacheReadTokens") or 0},
        "completion_tokens_details": {"reasoning_tokens": usage.get("reasoningTokens") or 0},
    }


def routable_model_ids(snapshot: dict) -> set[str]:
    membership = set(snapshot["membership"].get(ROUTE_MAIN, []))
    if snapshot.get("settings", {}).get("exposeRegionModels") is not False:
        membership |= set(snapshot["membership"].get(f"{ROUTE_MAIN}-region", []))
    return membership


def create_forward_completion(*, adapter, state: Callable[[], dict], stop_event=None, channel_stream=None,
                              record_usage=None, record_log=None):
    """固定本次请求的模型和配置快照；两个入口共用同一条推理链路。"""
    usage_sink = record_usage if callable(record_usage) else (lambda record: None)
    log_sink = record_log if callable(record_log) else (lambda record: None)

    def write_log(*, started, model, channel, stream, outcome, error, first_at, request_body):
        try:
            log_sink(_log_record(started=started, model=model, channel=channel, stream=stream,
                                 outcome=outcome, error=error, first_at=first_at, request_body=request_body))
        except Exception:  # noqa: BLE001  日志本身绝不能影响转发
            pass

    async def complete(request: dict, on_chunk=None):
        snapshot = state()
        requested = str(request.get("model") or "")
        entry = next((c for c in snapshot["catalog"] if c["id"] == request["model"]), None)
        if entry is None or entry["id"] not in routable_model_ids(snapshot):
            write_log(started=int(time.time() * 1000), model=requested, channel="", stream=bool(on_chunk),
                      outcome={}, error=NotFound(f'model "{requested}" not found or not routable'),
                      first_at=None, request_body=request.get("openAi") or {})
            raise NotFound(f'model "{request["model"]}" not found')
        open_ai = request.get("openAi") or {}
        handler = on_chunk if callable(on_chunk) else (lambda chunk: None)
        outcome = {"text": "", "toolCalls": [], "usage": None, "truncated": False, "error": None}
        started = int(time.time() * 1000)
        # 首个 chunk 到达时刻 → 首字延迟。
        first = {"at": None}

        def emit(chunk):
            if first["at"] is None:
                first["at"] = int(time.time() * 1000)
            handler(chunk)

        channel = entry.get("channel")
        try:
            if channel and channel not in ("eac", "kilo") and channel_stream is not None:
                # 账号渠道（CodeArts 等）：直接交给渠道适配器，请求体沿用调用方的 OpenAI 形状。
                try:
                    async for chunk in channel_stream(entry, open_ai):
                        emit(chunk)
                        fold_forward_outcome(outcome, chunk)
                except Exception as error:  # noqa: BLE001  渠道内部失败也当作本轮失败
                    outcome["error"] = str(error)
                if outcome["truncated"] is True:
                    outcome["toolCalls"] = [c for c in outcome["toolCalls"] if _is_json(c.get("arguments", ""))]
                usage = outcome.get("usage") or {}
                usage_sink({
                    "at": started, "model": entry["id"], "effort": "",
                    "ok": outcome["error"] is None,
                    "input": usage.get("prompt_tokens", 0), "output": usage.get("completion_tokens", 0),
                    "reasoning": (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0),
                    "cacheRead": (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
                    "decodeTokens": usage.get("completion_tokens", 0),
                    "ttftMs": None, "decodeMs": 0, "origin": f"channel:{channel}",
                    **({"truncated": True} if outcome["truncated"] else {}),
                })
            else:
                tools = [t for t in (normalize_tool(t) for t in (open_ai.get("tools") or [])) if t]
                options = {
                    "provider": ROUTE_MAIN, "model": entry["id"],
                    "messages": from_openai_messages(open_ai, request.get("responses") is True, entry["id"]),
                    "tools": tools or None,
                    "sessionId": f"forward:{open_ai.get('user') or open_ai.get('conversation') or 'shared'}",
                    "abortEvent": request.get("abortEvent") or stop_event,
                }
                if isinstance(open_ai.get("temperature"), (int, float)):
                    options["temperature"] = open_ai["temperature"]
                if isinstance(open_ai.get("max_tokens"), int):
                    options["maxTokens"] = open_ai["max_tokens"]
                if isinstance(open_ai.get("reasoning_effort"), str):
                    options["reasoningEffort"] = open_ai["reasoning_effort"]
                async for chunk in adapter.run_stream(options, entry, snapshot):
                    emit(chunk)
                    fold_forward_outcome(outcome, chunk)
                if outcome["truncated"] is True:
                    outcome["toolCalls"] = [c for c in outcome["toolCalls"] if _is_json(c.get("arguments", ""))]
        except BaseException as error:
            write_log(started=started, model=entry["id"], channel=channel or ROUTE_MAIN, stream=True,
                      outcome=outcome, error=error, first_at=first["at"], request_body=open_ai)
            raise
        write_log(started=started, model=entry["id"], channel=channel or ROUTE_MAIN,
                  stream=bool(on_chunk), outcome=outcome, error=None,
                  first_at=first["at"], request_body=open_ai)
        return outcome

    return complete


def _log_record(*, started: int, model: str, channel: str, stream: bool, outcome: dict,
                error: BaseException | None, first_at: int | None, request_body: dict) -> dict:
    """一次调用的日志记录（列表页字段 + 请求/响应预览）。"""
    usage = outcome.get("usage") or {}
    failed = error is not None or outcome.get("error") is not None
    if error is not None:
        message = str(getattr(error, "message", "") or error) or type(error).__name__
    elif outcome.get("error") is not None:
        message = str(outcome["error"])
    else:
        message = ""
    record = {
        "at": started,
        "model": model,
        "channel": channel,
        "stream": bool(stream),
        "ok": not failed,
        "status": 200 if not failed else int(getattr(error, "status_code", 0) or 502),
        "code": getattr(error, "code", None) or ("MODEL_ERROR" if failed else ""),
        "error": message,
        "latencyMs": max(0, int(time.time() * 1000) - started),
        "ttftMs": (first_at - started) if first_at else None,
        "input": usage.get("prompt_tokens", 0),
        "output": usage.get("completion_tokens", 0),
        "reasoning": (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0),
        "cacheRead": (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
        "truncated": outcome.get("truncated") is True,
        "request": preview(request_body),
        "response": preview(outcome.get("text") or ""),
    }
    if error is not None:
        record["errorType"] = type(error).__name__
    return record


class NotFound(Exception):
    status_code = 404


def _is_json(text: str) -> bool:
    try:
        json.loads(text if text != "" else "{}")
        return True
    except ValueError:
        return False


def from_openai_messages(body: dict, is_responses: bool, model_id: str) -> list[dict]:
    out: list[dict] = []
    rows = normalize_responses_input(body.get("input")) if is_responses else (body.get("messages") if isinstance(body.get("messages"), list) else [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        role = row.get("role") or "user"
        content: list = []
        raw = row.get("content")
        if isinstance(raw, str):
            if raw != "":
                content.append({"type": "text", "text": raw})
        elif isinstance(raw, list):
            for part in raw:
                if isinstance(part, str):
                    if part != "":
                        content.append({"type": "text", "text": part})
                    continue
                if isinstance(part, dict):
                    text = part.get("text") or part.get("input_text") or part.get("output_text")
                    if isinstance(text, str) and text != "":
                        content.append({"type": "text", "text": text})
                    image = part.get("image_url")
                    if isinstance(image, dict):
                        image = image.get("url")
                    if isinstance(image, str) and image != "":
                        content.append({"type": "image", "attachment": {
                            "attachmentId": f"url:{image[:64]}", "mediaType": "image/png",
                            "bytes": 0, "width": 0, "height": 0, "url": image}})
        if role == "tool":
            out.append({"role": "tool",
                        "content": [{"type": "text", "text": raw if isinstance(raw, str) else json.dumps(raw or "")}],
                        "toolCallId": row.get("tool_call_id", ""),
                        "source": {"kind": "tool", "callId": row.get("tool_call_id", "")}})
            continue
        if role == "assistant" and isinstance(row.get("tool_calls"), list):
            for call in row["tool_calls"]:
                fn = call.get("function") or {}
                content.append({"type": "tool-call", "id": call.get("id", ""),
                                "name": fn.get("name", ""), "arguments": fn.get("arguments", "{}")})
        if not content:
            continue
        mapped_role = "developer" if role == "developer" else role if role in ("system", "assistant", "user") else "user"
        entry = {"role": mapped_role, "content": content}
        if role == "assistant":
            entry["source"] = {"kind": "model", "provider": ROUTE_MAIN, "model": str(model_id or "")}
        out.append(entry)
    return out


def normalize_responses_input(inp):
    if isinstance(inp, str):
        return [{"role": "user", "content": inp}]
    if not isinstance(inp, list):
        return []
    out = []
    for row in inp:
        if isinstance(row, str):
            out.append({"role": "user", "content": row})
        elif isinstance(row, dict) and row.get("type") == "function_call":
            out.append({"role": "assistant", "content": [],
                        "tool_calls": [{"id": row.get("call_id"), "function": {"name": row.get("name"), "arguments": row.get("arguments")}}]})
        elif isinstance(row, dict) and row.get("type") == "function_call_output":
            out.append({"role": "tool", "content": str(row.get("output", "")), "tool_call_id": row.get("call_id")})
        elif isinstance(row, dict):
            out.append(row)
    return out


def normalize_tool(tool):
    if not isinstance(tool, dict):
        return None
    name = tool.get("name") or (tool.get("function") or {}).get("name")
    if not isinstance(name, str) or name.strip() == "":
        return None
    parameters = tool.get("parameters") or (tool.get("function") or {}).get("parameters") or {"type": "object", "properties": {}}
    description = tool.get("description") or (tool.get("function") or {}).get("description") or ""
    return {"name": name, "description": str(description), "parameters": parameters}


def fold_forward_outcome(outcome: dict, chunk: dict) -> dict:
    ctype = chunk.get("type")
    if ctype == "text-delta":
        outcome["text"] += chunk.get("text", "")
    elif ctype == "tool-call-delta":
        call = next((c for c in outcome["toolCalls"] if c.get("slot") == chunk.get("index")), None)
        if call is None:
            call = {"slot": chunk.get("index"), "id": chunk.get("id", ""), "name": chunk.get("name", ""),
                    "arguments": chunk.get("argumentsDelta", "")}
            outcome["toolCalls"].append(call)
        else:
            call["arguments"] += chunk.get("argumentsDelta") or ""
        if chunk.get("name"):
            call["name"] = chunk["name"]
        if chunk.get("id"):
            call["id"] = chunk["id"]
    elif ctype == "block-end":
        block = chunk.get("block") or {}
        if block.get("type") == "tool-call" and not any(c.get("id") == block.get("id") for c in outcome["toolCalls"]):
            outcome["toolCalls"].append({"slot": chunk.get("index"), "id": block.get("id"),
                                         "name": block.get("name"), "arguments": block.get("arguments")})
    elif ctype == "usage":
        outcome["usage"] = to_openai_usage(chunk.get("usage"))
    elif ctype == "finish":
        reason = chunk.get("reason") or {}
        if reason.get("kind") == "max-tokens":
            outcome["truncated"] = True
        if reason.get("kind") in ("error", "aborted"):
            outcome["error"] = (reason.get("failure") or {}).get("message")
    return outcome
