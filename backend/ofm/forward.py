"""OpenAI 兼容端点逻辑。

其它本地工具用 base URL 说 OpenAI，本模块把这类请求翻译成内部调用，
并以调用方期望的拼写流式回传答案。

两条线卫生规则让回答对调用方可执行（issue #20「转发客户端无法调用工具」）：
- ``tool_calls[].index`` 从 0 重新编号；
- 指向指纹诱饵的工具调用被抑制。
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time

from starlette.responses import JSONResponse, Response, StreamingResponse

from .completion import to_openai_usage
from .upstream import FINGERPRINT_TOOLS, base_model_id

MAX_BODY_BYTES = 8 * 1024 * 1024
SSE_HEARTBEAT_S = 15.0

_CORS = {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, content-type, x-api-key",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-max-age": "600",
}


def json_response(status: int, payload: dict) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={"cache-control": "no-store", **_CORS})


def openai_error(status: int, etype: str, message: str, code=None) -> JSONResponse:
    return json_response(status, {"error": {"message": message, "type": etype, "param": None, "code": code}})


async def read_json(request) -> dict:
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HttpError(413, "request body too large")
    if len(body) == 0:
        return {}
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise HttpError(400, "request body is not valid JSON")


class HttpError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def create_tool_wire(body: dict) -> dict:
    declared = set()
    for tool in body.get("tools") if isinstance(body.get("tools"), list) else []:
        fn = tool.get("function") if isinstance(tool, dict) else None
        name = (fn or {}).get("name") if isinstance(fn, dict) else (tool.get("name") if isinstance(tool, dict) else None)
        if isinstance(name, str) and name != "":
            declared.add(name)
    slots: dict[int, int] = {}
    next_index = {"value": 0}
    classified: dict[int, bool] = {}
    held: dict[int, dict] = {}

    def executable(name: str) -> bool:
        return not (name in FINGERPRINT_TOOLS and name not in declared)

    def index_of(block_index: int) -> int:
        assigned = slots.get(block_index)
        if assigned is None:
            assigned = next_index["value"]
            next_index["value"] += 1
            slots[block_index] = assigned
        return assigned

    def admit(chunk: dict) -> dict:
        block_index = chunk.get("index")
        verdict = classified.get(block_index)
        if verdict is False:
            return {"kind": "drop"}
        name = chunk.get("name") if isinstance(chunk.get("name"), str) and chunk.get("name") != "" else None
        if verdict is True:
            return {"kind": "forward", "openAiIndex": index_of(block_index), "first": False,
                    "args": chunk.get("argumentsDelta") or ""}
        if name is not None:
            keep = executable(name)
            classified[block_index] = keep
            if not keep:
                return {"kind": "drop"}
            parked = held.pop(block_index, None)
            return {"kind": "forward", "openAiIndex": index_of(block_index), "first": True,
                    "id": chunk.get("id") or (parked or {}).get("id"), "name": name,
                    "args": "".join((parked or {}).get("args") or []) + (chunk.get("argumentsDelta") or "")}
        parked = held.get(block_index) or {"args": []}
        if chunk.get("id"):
            parked["id"] = chunk["id"]
        if chunk.get("argumentsDelta"):
            parked["args"].append(chunk["argumentsDelta"])
        held[block_index] = parked
        return {"kind": "drop"}

    return {"executable": executable, "indexOf": index_of, "admit": admit}


def executable_calls(outcome: dict, tools: dict) -> list[dict]:
    calls = [c for c in (outcome.get("toolCalls") or []) if tools["executable"](c.get("name", ""))]
    if outcome.get("truncated") is True:
        calls = [c for c in calls if _json_ok(c.get("arguments", ""))]
    return [{"id": c.get("id") or f"call_{i}", "name": c.get("name"), "arguments": c.get("arguments")} for i, c in enumerate(calls)]


def _json_ok(text: str) -> bool:
    try:
        json.loads(text if text != "" else "{}")
        return True
    except ValueError:
        return False


class _Sentinel:
    pass


SENTINEL = _Sentinel()


async def _pump(complete, request: dict, queue: asyncio.Queue) -> None:
    try:
        outcome = await complete(request, lambda chunk: queue.put_nowait(chunk))
        queue.put_nowait(("__outcome__", outcome))
    except BaseException as error:  # noqa: BLE001
        queue.put_nowait(("__error__", error))
    finally:
        queue.put_nowait(SENTINEL)


async def _stream_frames(complete, request: dict, frames_for, final_frames, abort_event: asyncio.Event):
    """驱动一次流式回答：把 chunk 翻译成 SSE 帧。"""
    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.create_task(_pump(complete, request, queue))
    try:
        for frame in frames_for["open"]():
            yield frame
        outcome = None
        error = None
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=SSE_HEARTBEAT_S)
            except asyncio.TimeoutError:
                yield b": ping\n\n"
                continue
            if item is SENTINEL:
                break
            if isinstance(item, tuple):
                if item[0] == "__outcome__":
                    outcome = item[1]
                elif item[0] == "__error__":
                    error = item[1]
                continue
            for frame in frames_for["chunk"](item):
                yield frame
        for frame in final_frames(outcome, error):
            yield frame
    finally:
        abort_event.set()
        if not task.done():
            task.cancel()
        try:
            await task
        except BaseException:  # noqa: BLE001
            pass


def _sse_headers() -> dict:
    return {
        **_CORS,
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        "connection": "keep-alive",
        "x-accel-buffering": "no",
    }


async def handle_chat_completions(request, complete) -> Response:
    body = await read_json(request)
    import re
    effort_suffix = re.search(r"\(([^()]+)\)\s*$", str(body.get("model", "")))
    model = base_model_id(str(body.get("model", "")))
    if model == "":
        return openai_error(400, "invalid_request_error", "`model` is required")
    completion_id = f"chatcmpl-{secrets.token_hex(8)}"
    created = int(time.time())
    wants_stream = body.get("stream") is True
    if effort_suffix is not None and body.get("reasoning_effort") is None:
        body["reasoning_effort"] = effort_suffix.group(1).strip()
    tools = create_tool_wire(body)
    abort_event = asyncio.Event()

    if not wants_stream:
        try:
            outcome = await complete({"model": model, "openAi": body, "abortEvent": abort_event})
        except HttpError:
            raise
        except Exception as error:  # noqa: BLE001
            return openai_error(502, "server_error", _error_message(error))
        if outcome.get("error") is not None:
            return openai_error(502, "server_error", str(outcome["error"]))
        calls = executable_calls(outcome, tools)
        message = {"role": "assistant",
                   "content": None if outcome.get("text") in ("", None) else outcome["text"]}
        if calls:
            message["tool_calls"] = [{"id": c["id"], "type": "function",
                                      "function": {"name": c["name"], "arguments": c["arguments"]}} for c in calls]
        return json_response(200, {
            "id": completion_id, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0, "message": message,
                         "finish_reason": "tool_calls" if calls else "length" if outcome.get("truncated") else "stop"}],
            "usage": outcome.get("usage") or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def frames_for():
        def open_frames():
            yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                        "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]})

        def chunk_frames(chunk):
            ctype = chunk.get("type")
            if ctype == "text-delta":
                yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                            "choices": [{"index": 0, "delta": {"content": chunk.get("text")}, "finish_reason": None}]})
                return
            if ctype == "reasoning-delta":
                yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                            "choices": [{"index": 0, "delta": {"reasoning": chunk.get("text")}, "finish_reason": None}]})
                return
            if ctype == "tool-call-delta":
                action = tools["admit"](chunk)
                if action["kind"] == "drop":
                    return
                delta = {"tool_calls": [{"index": action["openAiIndex"],
                                         **({"id": action.get("id"), "function": {"name": action.get("name") or "", "arguments": ""}} if action["first"] else {})}]}
                yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                            "choices": [{"index": 0, "delta": delta, "finish_reason": None}]})
                if action.get("args"):
                    yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                                "choices": [{"index": 0, "delta": {"tool_calls": [{"index": action["openAiIndex"], "function": {"arguments": action["args"]}}]}, "finish_reason": None}]})
                return
            if ctype == "usage":
                yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                            "choices": [], "usage": to_openai_usage(chunk.get("usage"))})

        return {"open": open_frames, "chunk": chunk_frames}

    def final_frames(outcome, error):
        if error is not None:
            yield _sse({"error": {"message": _error_message(error), "type": "server_error"}})
            yield b"data: [DONE]\n\n"
            return
        if outcome is not None and outcome.get("error") is not None:
            yield _sse({"error": {"message": str(outcome["error"]), "type": "server_error"}})
            yield b"data: [DONE]\n\n"
            return
        calls = executable_calls(outcome or {}, tools)
        finish = "tool_calls" if calls else "length" if (outcome or {}).get("truncated") else "stop"
        yield _sse({"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]})
        yield b"data: [DONE]\n\n"

    frames = frames_for()
    return StreamingResponse(_stream_frames(complete, {"model": model, "openAi": body, "abortEvent": abort_event},
                                            frames, final_frames, abort_event),
                             status_code=200, headers=_sse_headers())


async def handle_responses(request, complete) -> Response:
    body = await read_json(request)
    import re
    effort_suffix = re.search(r"\(([^()]+)\)\s*$", str(body.get("model", "")))
    model = base_model_id(str(body.get("model", "")))
    if model == "":
        return openai_error(400, "invalid_request_error", "`model` is required")
    resp_id = f"resp-{secrets.token_hex(8)}"
    created = int(time.time())
    inp = []
    if isinstance(body.get("instructions"), str) and body["instructions"] != "":
        inp.append({"role": "system", "content": body["instructions"]})
    if isinstance(body.get("input"), list):
        inp.extend(body["input"])
    elif body.get("input") is not None:
        inp.append(body["input"])
    elif isinstance(body.get("messages"), list):
        inp.extend(body["messages"])
    open_ai = {**body, "input": inp}
    if isinstance(body.get("max_output_tokens"), int):
        open_ai["max_tokens"] = body["max_output_tokens"]
    if body.get("reasoning_effort") is None and effort_suffix is not None:
        open_ai["reasoning_effort"] = effort_suffix.group(1).strip()

    tools = create_tool_wire(open_ai)
    abort_event = asyncio.Event()

    def status_of(outcome):
        return "incomplete" if (outcome or {}).get("truncated") is True else "completed"

    if body.get("stream") is True:
        def frames_for():
            def open_frames():
                yield _sse_event("response.created", {"type": "response.created",
                                                      "response": {"id": resp_id, "object": "response",
                                                                   "created_at": created, "model": model,
                                                                   "status": "in_progress", "output": []}})

            state = {"next": 0, "messageIndex": None, "callIndexes": {}, "order": []}

            def chunk_frames(chunk):
                ctype = chunk.get("type")
                if ctype == "text-delta":
                    if state["messageIndex"] is None:
                        state["messageIndex"] = state["next"]
                        state["next"] += 1
                        state["order"].append("message")
                        yield _sse_event("response.output_item.added", {
                            "type": "response.output_item.added", "output_index": state["messageIndex"],
                            "item": {"type": "message", "role": "assistant", "item_id": f"msg_{state['messageIndex']}", "content": []}})
                    yield _sse_event("response.output_text.delta", {
                        "type": "response.output_text.delta", "item_id": f"msg_{state['messageIndex']}",
                        "output_index": state["messageIndex"], "delta": chunk.get("text")})
                    return
                if ctype == "tool-call-delta":
                    action = tools["admit"](chunk)
                    if action["kind"] == "drop":
                        return
                    oi = action["openAiIndex"]
                    if oi not in state["callIndexes"]:
                        index = state["next"]
                        state["next"] += 1
                        state["callIndexes"][oi] = index
                        state["order"].append(oi)
                        yield _sse_event("response.output_item.added", {
                            "type": "response.output_item.added", "output_index": index,
                            "item": {"type": "function_call", "item_id": f"fc_{index}", "call_id": f"fc_{index}",
                                     "name": action.get("name") or "", "arguments": ""}})
                    yield _sse_event("response.function_call_arguments.delta", {
                        "type": "response.function_call_arguments.delta",
                        "item_id": f"fc_{state['callIndexes'][oi]}", "output_index": state["callIndexes"][oi],
                        "delta": action.get("args")})
                    return

            return {"open": open_frames, "chunk": chunk_frames}

        def final_frames(outcome, error):
            if error is not None or (outcome or {}).get("error") is not None:
                message = _error_message(error) if error is not None else str(outcome["error"])
                yield _sse_event("response.failed", {"type": "response.failed",
                                                     "response": {"id": resp_id, "object": "response", "status": "failed",
                                                                  "error": {"message": message}}})
                return
            outcome = outcome or {}
            calls = executable_calls(outcome, tools)
            output = []
            if outcome.get("text"):
                output.append({"type": "message", "role": "assistant",
                               "content": [{"type": "output_text", "text": outcome["text"]}]})
            for call in calls:
                output.append({"type": "function_call", "call_id": call["id"], "name": call["name"], "arguments": call["arguments"]})
            usage = outcome.get("usage") or {}
            final = {"id": resp_id, "object": "response", "created_at": created, "model": model,
                     "status": status_of(outcome), "output": output,
                     **({"incomplete_details": {"reason": "max_output_tokens"}} if outcome.get("truncated") else {}),
                     "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0),
                               "total_tokens": usage.get("total_tokens", 0)}}
            yield _sse_event("response.completed", {"type": "response.completed", "response": final})

        frames = frames_for()
        return StreamingResponse(_stream_frames(complete, {"model": model, "openAi": open_ai, "responses": True,
                                                            "responsesBody": body, "abortEvent": abort_event},
                                                frames, final_frames, abort_event),
                                 status_code=200, headers=_sse_headers())

    try:
        outcome = await complete({"model": model, "openAi": open_ai, "responses": True,
                                  "responsesBody": body, "abortEvent": abort_event})
    except Exception as error:  # noqa: BLE001
        return openai_error(502, "server_error", _error_message(error))
    if outcome.get("error") is not None:
        return openai_error(502, "server_error", str(outcome["error"]))
    calls = executable_calls(outcome, tools)
    output = []
    if outcome.get("text"):
        output.append({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": outcome["text"]}]})
    for call in calls:
        output.append({"type": "function_call", "call_id": call["id"], "name": call["name"], "arguments": call["arguments"]})
    usage = outcome.get("usage") or {}
    return json_response(200, {
        "id": resp_id, "object": "response", "created_at": created, "model": model,
        "status": status_of(outcome), "output": output,
        **({"incomplete_details": {"reason": "max_output_tokens"}} if outcome.get("truncated") else {}),
        "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0),
                  "total_tokens": usage.get("total_tokens", 0)},
    })


def _sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _sse_event(event: str, payload: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _error_message(error) -> str:
    if isinstance(error, HttpError):
        return error.message
    status = getattr(error, "status_code", None)
    if isinstance(status, int) and 400 <= status <= 599:
        return str(getattr(error, "message", None) or error)
    return str(error)
