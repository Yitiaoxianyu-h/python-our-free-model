"""上游 SSE → 内部 StreamChunk 投影（三种线格式）。

内部块协议是扁平的带索引块：``block-start`` 开启、``*-delta`` 喂入、
``block-end`` 携带组装后的块关闭。块索引按到达顺序分配。

Token 计数遵循「不相交」规则：``inputTokens`` 只含未缓存输入，
故 OpenAI 的 ``prompt_tokens`` 要扣除缓存命中。
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Any, AsyncIterator, Callable

from .http_client import classify_failure

# DeepSeek v4 系偶尔把内部 DSML 控制标记泄漏进可见正文，流出时清洗。
DSML_OPENING = "<｜DSML｜"
DSML_TAG = re.compile(r"<｜DSML｜[^>]*>")


class _DsmlScrubber:
    def __init__(self) -> None:
        self._held = ""

    def push(self, delta: str) -> str:
        text = self._held + delta
        self._held = ""
        cut = text.rfind("<")
        if cut != -1:
            tail = text[cut:]
            if DSML_OPENING.startswith(tail) or (tail.startswith(DSML_OPENING) and ">" not in tail):
                self._held = tail
                text = text[:cut]
        return DSML_TAG.sub("", text)

    def flush(self) -> str:
        out, self._held = self._held, ""
        if out == "" or DSML_OPENING.startswith(out) or (out.startswith(DSML_OPENING) and ">" not in out):
            return ""
        return DSML_TAG.sub("", out)


def _mint_tool_call_id() -> str:
    return f"call_{secrets.token_hex(12)}"


class BlockSink:
    def __init__(self, emit: Callable[[dict], None], start_index: int, checkpoint_limit: int) -> None:
        self.emit = emit
        self.next = start_index
        self.open: dict[str, dict] = {}
        self.usage = None
        self.saw_reasoning = False
        self.saw_text = False
        self.saw_tool_call = False
        self.reasoning_text = ""
        self.answer_text = ""
        self.answer_limit = checkpoint_limit
        self.checkpoint_limit = checkpoint_limit
        self.checkpoint_truncated = False
        self.broken_tool_call = False
        self.last_tool_key: str | None = None
        self.dsml = _DsmlScrubber()

    def tool_key(self, call: dict) -> str:
        index = call.get("index")
        if index is not None:
            self.last_tool_key = f"c{index}"
            return self.last_tool_key
        cid = call.get("id")
        if isinstance(cid, str) and cid != "":
            for key, block in self.open.items():
                if block["kind"] == "tool-call" and block["id"] == cid:
                    self.last_tool_key = key
                    return key
            self.last_tool_key = f"cid:{cid}"
            return self.last_tool_key
        return self.last_tool_key or "c0"

    def slot(self, key: str, kind: str) -> dict:
        if kind == "tool-call":
            self.saw_tool_call = True
        existing = self.open.get(key)
        if existing is not None:
            return existing
        block = {"index": self.next, "kind": kind, "text": "", "args": "",
                 "id": _mint_tool_call_id() if kind == "tool-call" else "", "name": ""}
        self.next += 1
        self.open[key] = block
        self.emit({"type": "block-start", "index": block["index"],
                   "blockType": "reasoning" if kind == "reasoning" else "tool-call" if kind == "tool-call" else "text"})
        return block

    def text(self, key: str, delta: str | None) -> None:
        if delta is None or delta == "":
            return
        scrubbed = self.dsml.push(delta)
        if scrubbed == "":
            return
        self.saw_text = True
        if len(self.answer_text) < self.answer_limit:
            room = self.answer_limit - len(self.answer_text)
            self.answer_text += scrubbed[:room]
        block = self.slot(key, "text")
        block["text"] += scrubbed
        self.emit({"type": "text-delta", "index": block["index"], "text": scrubbed})

    def reasoning(self, key: str, delta: str | None) -> None:
        if delta is None or delta == "":
            return
        self.saw_reasoning = True
        text = str(delta)
        remaining = self.checkpoint_limit - len(self.reasoning_text)
        if len(text) > remaining:
            self.checkpoint_truncated = True
        self.reasoning_text += text[: max(0, remaining)]
        block = self.slot(key, "reasoning")
        block["text"] += delta
        self.emit({"type": "reasoning-delta", "index": block["index"], "text": delta})

    def tool_start(self, key: str, call_id: str, name: str) -> None:
        block = self.slot(key, "tool-call")
        if call_id:
            block["id"] = call_id
        if name:
            block["name"] = name

    def tool_args(self, key: str, delta: str | None) -> None:
        self.saw_tool_call = True
        if not delta:
            return
        block = self.slot(key, "tool-call")
        block["args"] += delta
        name = {"name": block["name"]} if isinstance(block["name"], str) and block["name"] != "" else {}
        self.emit({"type": "tool-call-delta", "index": block["index"], "id": block["id"] or "",
                   **name, "argumentsDelta": delta})

    def close_all(self) -> None:
        spill = self.dsml.flush()
        spilled = False
        for block in self.open.values():
            if block["kind"] == "text" and not spilled and spill != "":
                spilled = True
                block["text"] += spill
                self.emit({"type": "text-delta", "index": block["index"], "text": spill})
            if block["kind"] == "text" and block["text"] != "":
                self.emit({"type": "block-end", "index": block["index"], "block": {"type": "text", "text": block["text"]}})
            elif block["kind"] == "reasoning" and block["text"] != "":
                self.emit({"type": "block-end", "index": block["index"], "block": {"type": "reasoning", "text": block["text"]}})
            elif block["kind"] == "tool-call":
                try:
                    json.loads(block["args"] if block["args"] != "" else "{}")
                except ValueError:
                    self.broken_tool_call = True
                if not isinstance(block["name"], str) or block["name"] == "":
                    self.broken_tool_call = True
                self.emit({"type": "block-end", "index": block["index"],
                           "block": {"type": "tool-call", "id": block["id"] or "", "name": block["name"] or "",
                                     "arguments": block["args"] if block["args"] != "" else "{}"}})
        self.open.clear()


def map_usage(usage: Any) -> dict | None:
    """把上游 ``usage`` 转成不相交的 TokenUsage。"""
    if not isinstance(usage, dict):
        return None

    def number(value):
        return value if isinstance(value, (int, float)) and value == value else None

    prompt = number(usage.get("prompt_tokens", usage.get("input_tokens")))
    completion = number(usage.get("completion_tokens", usage.get("output_tokens")))
    details = usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
    in_details = usage.get("input_tokens_details") if isinstance(usage.get("input_tokens_details"), dict) else {}
    cached = number(details.get("cached_tokens", in_details.get("cached_tokens"))) or 0
    cache_write = number(details.get("cache_write_tokens")) or 0
    out_details = usage.get("completion_tokens_details") if isinstance(usage.get("completion_tokens_details"), dict) else {}
    reasoning = number(out_details.get("reasoning_tokens", usage.get("output_tokens_details", {}).get("reasoning_tokens")
                       if isinstance(usage.get("output_tokens_details"), dict) else None))
    if prompt is None and completion is None:
        return None
    out: dict[str, Any] = {
        "inputTokens": max(0, (prompt or 0) - cached),
        "outputTokens": completion or 0,
    }
    if cached > 0:
        out["cacheReadTokens"] = cached
    if cache_write > 0:
        out["cacheWriteTokens"] = cache_write
    if reasoning:
        out["reasoningTokens"] = reasoning
    out["totalTokens"] = (prompt or 0) + (completion or 0)
    return out


REASONING_FIELDS = ("reasoning", "reasoning_content", "reasoning_text", "thinking")


def reasoning_of(delta: dict) -> str | None:
    for field in REASONING_FIELDS:
        value = delta.get(field)
        if isinstance(value, str) and value != "":
            return value
    details = delta.get("reasoning_details")
    if isinstance(details, list):
        text = "".join(part.get("text", "") for part in details if isinstance(part, dict) and isinstance(part.get("text"), str))
        if text != "":
            return text
    return None


def finish_reason(token: str | None) -> dict:
    if token in ("tool_calls", "tool_use", "function_call"):
        return {"kind": "tool-calls"}
    if token in ("length", "max_tokens", "max_output_tokens", "incomplete"):
        return {"kind": "max-tokens"}
    return {"kind": "stop"}


def window_tokens(usage: dict | None, saw_reasoning: bool) -> int:
    output = usage.get("outputTokens", 0) if usage else 0
    if not isinstance(output, (int, float)):
        output = 0
    if saw_reasoning:
        return int(output)
    reasoning = usage.get("reasoningTokens", 0) if usage else 0
    reasoning = reasoning if isinstance(reasoning, (int, float)) else 0
    return int(max(0, output - reasoning))


def _feed_chat(sink: BlockSink, payload: dict, rename: dict[str, str] | None, on_finish) -> None:
    if payload.get("usage"):
        on_finish(map_usage(payload["usage"]), "usage", None)
    for choice in payload.get("choices") or []:
        delta = choice.get("delta") or {}
        reasoning = reasoning_of(delta)
        if reasoning is not None:
            sink.reasoning("r", reasoning)
        if isinstance(delta.get("content"), str):
            sink.text("t", delta["content"])
        for call in delta.get("tool_calls") or []:
            sink.saw_tool_call = True
            key = sink.tool_key(call)
            fn = call.get("function") or {}
            name = fn.get("name")
            if isinstance(name, str) and name != "":
                from .upstream import restore_tool_name
                sink.tool_start(key, call.get("id", ""), restore_tool_name(name, rename))
            elif call.get("id"):
                sink.tool_start(key, call["id"], "")
            if fn.get("arguments"):
                sink.tool_args(key, fn["arguments"])
        if choice.get("finish_reason"):
            on_finish(None, "finish", choice["finish_reason"])


def _feed_claude(sink: BlockSink, event: dict, on_finish, rename: dict[str, str] | None) -> None:
    from .upstream import restore_tool_name
    etype = event.get("type")
    if etype == "content_block_start":
        block = event.get("content_block")
        if isinstance(block, dict) and block.get("type") == "tool_use":
            sink.tool_start(f"b{event.get('index')}", block.get("id", ""), restore_tool_name(block.get("name", ""), rename))
        return
    if etype == "content_block_delta":
        part = event.get("delta") or {}
        if part.get("type") == "text_delta":
            sink.text(f"b{event.get('index')}", part.get("text"))
        elif part.get("type") == "thinking_delta":
            sink.reasoning(f"b{event.get('index')}", part.get("thinking"))
        elif part.get("type") == "input_json_delta":
            sink.tool_args(f"b{event.get('index')}", part.get("partial_json"))
        return
    if etype == "message_start":
        usage = (event.get("message") or {}).get("usage")
        if usage:
            mapped = map_usage({
                "prompt_tokens": usage.get("input_tokens"),
                "completion_tokens": usage.get("output_tokens"),
                "prompt_tokens_details": {"cached_tokens": usage.get("cache_read_input_tokens"),
                                          "cache_write_tokens": usage.get("cache_creation_input_tokens")},
            })
            if mapped:
                on_finish(mapped, "usage", None)
        return
    if etype == "message_delta":
        usage = event.get("usage")
        if usage and usage.get("output_tokens") is not None:
            on_finish({"outputTokens": usage.get("output_tokens")}, "usage", None)
        stop = (event.get("delta") or {}).get("stop_reason")
        if stop:
            on_finish(None, "finish", stop)
        return
    if etype == "message_stop":
        on_finish(None, "finish", None)


def _feed_responses(sink: BlockSink, event: dict, on_finish, rename: dict[str, str] | None) -> None:
    from .upstream import restore_tool_name
    etype = event.get("type")
    if etype == "response.output_item.added":
        item = event.get("item") or {}
        if item.get("type") == "function_call":
            sink.tool_start(f"i{event.get('output_index')}", item.get("call_id") or item.get("id") or "",
                            restore_tool_name(item.get("name", ""), rename))
        return
    if etype == "response.output_text.delta":
        sink.text(f"t{event.get('output_index')}", event.get("delta"))
        return
    if etype in ("response.reasoning_summary_text.delta", "response.output_reasoning.text.delta"):
        sink.reasoning(f"r{event.get('item_id', 'r')}", event.get("delta"))
        return
    if etype == "response.function_call_arguments.delta":
        sink.tool_args(f"i{event.get('output_index')}", event.get("delta"))
        return
    if etype in ("response.completed", "response.incomplete", "response.failed", "response.done"):
        response = event.get("response")
        if isinstance(response, dict) and response.get("usage"):
            ru = response["usage"]
            mapped = map_usage({
                "prompt_tokens": ru.get("input_tokens"),
                "completion_tokens": ru.get("output_tokens"),
                "prompt_tokens_details": {"cached_tokens": (ru.get("input_tokens_details") or {}).get("cached_tokens")},
                "completion_tokens_details": {"reasoning_tokens": (ru.get("output_tokens_details") or {}).get("reasoning_tokens")},
            })
            if mapped:
                on_finish(mapped, "usage", None)
        status = (response or {}).get("status") if isinstance(response, dict) else None
        status = status or ("failed" if etype == "response.failed"
                            else "incomplete" if etype == "response.incomplete"
                            else "completed" if etype == "response.completed" else None)
        incomplete = (response or {}).get("incomplete_details", {}).get("reason") if isinstance(response, dict) else None
        on_finish(None, "finish", "length" if incomplete == "max_output_tokens" else ("stop" if status == "completed" else status))
        return


def _carries_delta(payload: dict, wire: str) -> bool:
    if wire == "chat":
        for choice in payload.get("choices") or []:
            delta = choice.get("delta") or {}
            if isinstance(delta.get("content"), str) and delta["content"] != "":
                return True
            if reasoning_of(delta) is not None:
                return True
            if delta.get("tool_calls"):
                return True
        return False
    if wire == "responses":
        return (isinstance(payload.get("delta"), str) and payload["delta"] != "") or payload.get("type") == "response.output_item.added"
    return payload.get("type") in ("content_block_delta", "content_block_start")


class StreamReader:
    """一次流式读取：逐步产出 chunk，结束时给出汇总 state。"""

    def __init__(self, lines: AsyncIterator[str], wire: str, rename: dict[str, str] | None,
                 now: Callable[[], float], start_index: int = 0, checkpoint_limit: int = 131072,
                 on_state: Callable[[dict], None] | None = None) -> None:
        self._lines = lines
        self._wire = wire
        self._rename = rename
        self._now = now
        self._on_state = on_state
        self._outbox: list[dict] = []
        self._sink = BlockSink(self._outbox.append, start_index, checkpoint_limit)
        self._state = {"usage": None, "finish": None, "sawFinish": False, "sawUsage": False,
                       "sawToolCall": False, "firstDeltaAt": None, "sawReasoning": False,
                       "sawText": False, "brokenToolCall": False}
        self._gen = self._run()

    def _snapshot(self) -> dict:
        return {
            **self._state,
            "nextIndex": self._sink.next,
            "reasoningText": self._sink.reasoning_text,
            "answerText": self._sink.answer_text,
            "checkpointTruncated": self._sink.checkpoint_truncated,
            "usage": self._state["usage"] or {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
        }

    def _publish(self) -> None:
        if self._on_state is not None:
            self._on_state(self._snapshot())

    def _on_finish(self, usage, kind, token) -> None:
        if kind == "usage" and usage is not None:
            self._state["sawUsage"] = True
            carried = self._state["usage"]
            if carried is not None and usage.get("inputTokens") is None:
                merged = {**carried, **usage}
                merged["totalTokens"] = max(0, (carried.get("totalTokens") or 0) - (carried.get("outputTokens") or 0)) + (usage.get("outputTokens") or 0)
                self._state["usage"] = merged
            else:
                self._state["usage"] = usage
        if kind != "finish":
            return
        self._state["sawFinish"] = True
        if token is not None:
            self._state["finish"] = token

    async def _run(self) -> AsyncIterator[dict]:
        try:
            async for raw in self._lines:
                if not isinstance(raw, str):
                    continue
                text = raw.strip()
                if not text.startswith("{"):
                    continue
                try:
                    payload = json.loads(text)
                except ValueError:
                    continue
                if payload.get("type") == "error" or payload.get("error"):
                    failure = payload.get("error") or payload
                    classified = classify_failure(None, payload)
                    if not isinstance(failure.get("message"), str):
                        classified.message = "upstream error"
                    classified.upstream = payload
                    raise classified
                if self._state["firstDeltaAt"] is None and _carries_delta(payload, self._wire):
                    self._state["firstDeltaAt"] = self._now()
                if self._wire == "chat":
                    _feed_chat(self._sink, payload, self._rename, self._on_finish)
                elif self._wire == "messages":
                    _feed_claude(self._sink, payload, self._on_finish, self._rename)
                else:
                    _feed_responses(self._sink, payload, self._on_finish, self._rename)
                if self._sink.saw_reasoning:
                    self._state["sawReasoning"] = True
                if self._sink.saw_text:
                    self._state["sawText"] = True
                if self._sink.broken_tool_call:
                    self._state["brokenToolCall"] = True
                if self._sink.saw_tool_call:
                    self._state["sawToolCall"] = True
                self._publish()
                while self._outbox:
                    yield self._outbox.pop(0)
            self._sink.close_all()
            if self._sink.broken_tool_call:
                self._state["brokenToolCall"] = True
            self._publish()
            while self._outbox:
                yield self._outbox.pop(0)
        except BaseException:
            self._publish()
            raise

    async def next(self) -> tuple[bool, Any]:
        try:
            chunk = await self._gen.__anext__()
            return False, chunk
        except StopAsyncIteration:
            return True, self._snapshot()

    async def close(self) -> None:
        try:
            await self._gen.aclose()
        except Exception:
            pass


def read_stream(lines: AsyncIterator[str], wire: str, rename: dict[str, str] | None = None,
                now: Callable[[], float] | None = None, start_index: int = 0,
                checkpoint_limit: int = 131072, on_state: Callable[[dict], None] | None = None) -> StreamReader:
    import time as _time
    return StreamReader(lines, wire, rename, now or (lambda: _time.time() * 1000),
                        start_index, checkpoint_limit, on_state)
