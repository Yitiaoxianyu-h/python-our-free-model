"""提供方适配器：免费车道一轮对话的完整主流程。

结构性实现（不依赖任何宿主基类）：两条 provider 路由（主 / 地区受限）
共用同一实例。区域受限的标题需要单独一条路由来呈现。
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator, Callable

from .catalog import is_eac_entry, is_kilo_entry
from .channel import create_channel
from .effort import (
    DEFAULT_LEVEL,
    budget_for,
    default_effort_for,
    efforts_for,
    effort_patch_for,
    resolve_level,
)
from .http_client import CODE, UpstreamError, post_streamed
from .kilo import post_kilo_streamed
from .messages import repair_tool_pairing, to_chat_messages, to_claude_messages, to_response_input, to_tool_defs
from .recovery import (
    add_usage,
    can_recover,
    can_recover_silent_stop,
    checkpoint_fits,
    continuation_messages,
    create_block_tracker,
    recovery_messages,
    recovery_policy,
)
from .effort import MIN_BUDGET
from .stream import finish_reason, read_stream, window_tokens
from .upstream import (
    apply_fingerprint,
    base_model_id,
    endpoint_for,
    mint_request_id,
    session_for_conversation,
    wire_for,
)

ROUTE_MAIN = "our-free-model"
ROUTE_REGION = "our-free-model-region"

ROUTE_LABELS = {
    ROUTE_MAIN: "Our Free Model",
    ROUTE_REGION: "Our Free Model · region-limited",
}

STYLE_FOR_WIRE = {"chat": "chat", "responses": "flat", "messages": "claude"}

SEALED_PACING_HINT = "Avoid overthinking: keep your reasoning brief and proportionate to the task."


def _ms() -> float:
    return time.time() * 1000


class FreeModelAdapter:
    def __init__(self, *, state, resolve_image=None, sealed_credential=None,
                 record_usage=None, record_turn=None, warn=None, on_region_blocked=None):
        self.deps = {
            "state": state,
            "resolveImage": resolve_image,
            "sealedCredential": sealed_credential or (lambda: None),
            "recordUsage": record_usage or (lambda record: None),
            "recordTurn": record_turn or (lambda record: None),
            "warn": warn or (lambda message: None),
            "onRegionBlocked": on_region_blocked or (lambda model_id: None),
        }

    def provider_info(self, provider: str) -> dict:
        return {"id": provider, "name": ROUTE_LABELS.get(provider, provider)}

    def provider_retry_policy(self) -> dict:
        return {
            "mode": "normal", "maxRetries": 2,
            "retryableCodes": ["EMPTY_RESPONSE", "SERVER", "TIMEOUT", "TRANSPORT"],
            "initialDelayMs": 700, "maxDelayMs": 8000, "jitterRatio": 0.2,
        }

    async def list_models(self, provider: str) -> list[dict]:
        state = self.deps["state"]()
        ids = set(state["membership"].get(provider, []))
        return [{
            "provider": provider, "id": entry["id"], "name": entry["name"],
            "description": describe(entry, state.get("settings")),
            "inputModalities": ["text", "image"] if entry.get("vision") else ["text"],
        } for entry in state["catalog"] if entry["id"] in ids]

    async def resolve_model(self, provider: str, model: str) -> dict:
        state = self.deps["state"]()
        entry = next((c for c in state["catalog"] if c["id"] == base_model_id(model)), None)
        if entry is None:
            return {"provider": provider, "id": base_model_id(model), "name": base_model_id(model),
                    "context": {"contextWindow": 131072}, "defaultMaxTokens": 8192}
        ceiling = min(entry.get("maxOutput", 32768), state.get("settings", {}).get("defaultMaxTokens") or 32768)
        efforts = efforts_for(entry, None, state.get("settings", {}).get("defaultMaxTokens"))
        out = {
            "provider": provider, "id": entry["id"], "name": entry["name"],
            "inputModalities": ["text", "image"] if entry.get("vision") else ["text"],
            "context": {"contextWindow": entry.get("contextWindow")},
            "defaultMaxTokens": ceiling,
        }
        if efforts is not None:
            out["reasoning"] = {"efforts": efforts, "defaultEffort": default_effort_for(entry)}
        return out

    async def run_stream(self, options: dict, pinned: dict | None = None, snapshot: dict | None = None) -> AsyncIterator[dict]:
        deps = self.deps
        snapshot = snapshot if snapshot is not None else deps["state"]()
        settings = snapshot.get("settings") or {}
        started = _ms()
        model_id = base_model_id(options.get("model"))
        abort_event: asyncio.Event | None = options.get("abortEvent")

        def record_rejected_turn():
            deps["recordTurn"]({"at": started, "model": model_id, "ok": False, "recovered": False, "attempts": 0, "origin": "harness"})

        entry = pinned or next((c for c in snapshot["catalog"] if c["id"] == model_id), None)
        if settings.get("enabled") is False:
            record_rejected_turn()
            yield {"type": "finish", "reason": {"kind": "error", "failure": {"message": "our free model is switched off in its settings page", "code": "CONFIG_DISABLED"}}}
            return
        if entry is None:
            record_rejected_turn()
            yield {"type": "finish", "reason": {"kind": "error", "failure": {"message": f'our free model does not serve "{options.get("model")}" on this egress', "code": CODE["server"]}}}
            return

        sealed = is_eac_entry(entry)
        kilo = is_kilo_entry(entry)
        wire = "chat" if (sealed or kilo) else wire_for(entry["id"])
        style = STYLE_FOR_WIRE[wire]
        warnings: list[str] = []
        messages = repair_tool_pairing(options.get("messages") or [])
        budget = budget_for(options.get("reasoningEffort"), entry, options.get("maxTokens"), settings.get("defaultMaxTokens"))
        declared = to_tool_defs(options.get("tools"), style)
        policy = recovery_policy(settings.get("streamRecovery"))
        session = session_for_conversation(options.get("sessionId"))
        recovery_id = mint_request_id()
        attempt_messages = messages
        attempt_budget = budget
        next_index = 0
        total_usage = {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0}
        blocks = create_block_tracker()
        turn_recorded = False

        def finish_turn(ok: bool, recovered: bool = False, attempts: int = 1):
            nonlocal turn_recorded
            if turn_recorded:
                return
            turn_recorded = True
            deps["recordTurn"]({"at": started, "model": entry["id"], "ok": ok, "recovered": recovered, "attempts": attempts, "origin": "harness"})

        def payload_for(input_messages, ceiling, recovering, sink):
            payload = build_payload(wire, entry["id"], input_messages, options, ceiling, deps["resolveImage"], sink)
            if declared:
                payload["tools"] = declared
            temperature = options.get("temperature")
            if isinstance(temperature, (int, float)):
                payload["temperature"] = temperature
            if wire != "responses" and isinstance(options.get("stop"), list) and options["stop"]:
                payload["stop"] = options["stop"]
            if recovering:
                payload["tool_choice"] = {"type": "none"} if wire == "messages" else "none"
            if sealed or kilo:
                patch = effort_patch_for(options.get("reasoningEffort"), entry)
                if patch is not None:
                    payload.update(patch)
            if sealed:
                apply_sealed_pacing_hint(payload)
            return payload

        for attempt in range(2):
            if abort_event is not None and abort_event.is_set():
                finish_turn(False, False, attempt)
                if attempt > 0:
                    yield {"type": "usage", "usage": total_usage}
                yield {"type": "finish", "reason": {"kind": "aborted", "failure": {"message": "request aborted", "code": CODE["aborted"]}}}
                return
            attempt_started = _ms()
            recovering = attempt == 1
            payload = payload_for(attempt_messages, attempt_budget, recovering, [] if recovering else warnings)
            rename_map = {} if (sealed or kilo) else apply_fingerprint(payload, "claude" if wire == "messages" else style == "flat")

            remaining_ms = max(1, policy["totalTimeoutMs"] - (attempt_started - started))
            timeout_ms = min(policy["maxContinuationMs"], remaining_ms) if recovering else remaining_ms

            channel = create_channel()

            async def produce():
                try:
                    if sealed:
                        credential = deps["sealedCredential"]()
                        if credential is None:
                            raise UpstreamError("this model lane is not available on this host (no EAC gateway configured)",
                                                "LANE_LOCKED")
                        from .eac import post_sealed_streamed
                        await post_sealed_streamed(credential, payload, channel.push, int(timeout_ms))
                    elif kilo:
                        await post_kilo_streamed(payload, channel.push, int(timeout_ms))
                    else:
                        await post_streamed(endpoint_for(entry["id"]), payload, session,
                                            recovery_id if attempt == 0 else mint_request_id(),
                                            snapshot.get("attributionUserAgent"), channel.push, int(timeout_ms))
                    channel.push(None)
                except BaseException as error:  # noqa: BLE001
                    channel.push(error if isinstance(error, BaseException) else RuntimeError(str(error)))

            task = asyncio.create_task(produce())
            first_delta_at = None
            delivered = False
            saw_answer = False
            recorded = False
            continuation_scheduled = False
            partial_outcome: dict | None = None
            usage_added = False
            expired = {"value": False}

            def record(ok, outcome, extra=None):
                nonlocal recorded
                if recorded:
                    return
                recorded = True
                extra = extra or {}
                usage = outcome.get("usage") if outcome and outcome.get("sawUsage") is True else None
                deps["recordUsage"]({
                    "at": attempt_started, "model": entry["id"],
                    "effort": (resolve_level(options.get("reasoningEffort"), entry) or {}).get("id", "") if isinstance(resolve_level(options.get("reasoningEffort"), entry), dict) else "",
                    "ok": ok,
                    "input": (usage or {}).get("inputTokens", 0),
                    "output": (usage or {}).get("outputTokens", 0),
                    "reasoning": (usage or {}).get("reasoningTokens", 0),
                    "cacheRead": (usage or {}).get("cacheReadTokens", 0),
                    "decodeTokens": window_tokens(usage, outcome.get("sawReasoning") is True) if ok else 0,
                    "ttftMs": None if first_delta_at is None else first_delta_at - attempt_started,
                    "decodeMs": 0 if first_delta_at is None else _ms() - first_delta_at,
                    "origin": "harness", "recoveryId": recovery_id, "attempt": attempt,
                    "elapsedMs": _ms() - attempt_started,
                    **(JSON_ONLY(extra)),
                    **({} if outcome and outcome.get("sawUsage") is True else {"noUsage": True}),
                    **({} if not warnings else {"warnings": warnings}),
                })

            async def watchdog():
                await asyncio.sleep(timeout_ms / 1000.0)
                expired["value"] = True
                if not channel._ended:
                    channel.push(UpstreamError(f"our free model reached its {round(timeout_ms/1000)}s time limit before its finish token", CODE["timeout"]))

            watchdog_task = asyncio.create_task(watchdog()) if policy["enabled"] else None

            try:
                reader = read_stream(channel.read(), wire, rename_map, _ms, next_index, policy["checkpointLimit"],
                                     lambda value: None)
                # onState
                def _on_state(value):
                    nonlocal partial_outcome
                    partial_outcome = value
                reader._on_state = _on_state
                outcome = None
                try:
                    while True:
                        done, value = await reader.next()
                        if done:
                            outcome = value
                            break
                        chunk = value
                        if chunk.get("type") == "text-delta" and isinstance(chunk.get("text"), str) and chunk["text"].strip():
                            saw_answer = True
                        if recovering and (chunk.get("blockType") == "tool-call" or chunk.get("type") == "tool-call-delta"
                                           or (isinstance(chunk.get("block"), dict) and chunk["block"].get("type") == "tool-call")):
                            raise UpstreamError("our free model continuation unexpectedly requested a tool", "STREAM_CUT")
                        if chunk.get("type") in ("text-delta", "reasoning-delta", "tool-call-delta"):
                            delivered = True
                            if first_delta_at is None:
                                first_delta_at = _ms()
                        blocks["accept"](chunk)
                        yield chunk
                finally:
                    await reader.close()
                next_index = outcome["nextIndex"]
                total_usage = add_usage(total_usage, outcome.get("usage"), outcome.get("sawUsage") is True)
                usage_added = True
                if abort_event is not None and abort_event.is_set():
                    record(False, outcome, {"aborted": True})
                    finish_turn(False, False, attempt + 1)
                    yield {"type": "usage", "usage": total_usage}
                    yield {"type": "finish", "reason": {"kind": "aborted", "failure": {"message": "request aborted", "code": CODE["aborted"]}}}
                    return
                reason = {"kind": "max-tokens"} if outcome.get("brokenToolCall") is True else finish_reason(outcome.get("finish"))
                elapsed = _ms() - started
                interrupted = can_recover(outcome, policy, elapsed)
                max_tokens_cut = (
                    policy["enabled"] and not recovering and reason["kind"] == "max-tokens"
                    and outcome.get("brokenToolCall") is not True
                    and outcome.get("sawText") is True and outcome.get("sawToolCall") is not True
                    and isinstance(outcome.get("answerText"), str) and outcome["answerText"].strip() != ""
                )
                silent_stop = (
                    not interrupted and not max_tokens_cut and reason["kind"] == "stop"
                    and (outcome.get("finish") is None or outcome.get("finish") in ("stop", "end_turn", "stop_sequence"))
                    and can_recover_silent_stop(outcome, policy, elapsed)
                )
                if not recovering and (interrupted or silent_stop or max_tokens_cut):
                    remaining_tokens = budget - (outcome.get("usage", {}).get("outputTokens", 0) if outcome.get("sawUsage") else 0)
                    continuation_budget = min(remaining_tokens, policy["maxOutputTokens"])
                    next_messages = (continuation_messages(messages, outcome.get("answerText")) if max_tokens_cut
                                     else recovery_messages(messages, outcome.get("reasoningText")))
                    if continuation_budget >= MIN_BUDGET and checkpoint_fits(
                            payload_for(next_messages, continuation_budget, True, []), entry,
                            outcome.get("answerText") if max_tokens_cut else outcome.get("reasoningText"), continuation_budget):
                        record(False, outcome, {"truncated": True, "recoveryScheduled": True})
                        deps["warn"]("our-free-model: continuing once from the checkpoint")
                        attempt_messages = next_messages
                        attempt_budget = continuation_budget
                        continuation_scheduled = True
                        continue

                failed_ending = outcome.get("finish") in ("failed", "cancelled")
                normal_ending = outcome.get("finish") is None or outcome.get("finish") in ("stop", "end_turn", "stop_sequence")
                if outcome.get("sawFinish") is not True or failed_ending or (
                        recovering and (not saw_answer or outcome.get("sawToolCall") is True or reason["kind"] != "stop" or not normal_ending)):
                    seconds = round((_ms() - started) / 1000)
                    code = "STREAM_CUT" if (recovering or delivered or outcome.get("sawToolCall") is True) else (
                        CODE["server"] if failed_ending else CODE["transport"])
                    message = (
                        f"our free model continuation ended without a complete answer after {seconds}s; automatic recovery exhausted"
                        if recovering else
                        f"our free model upstream response ended with status {outcome.get('finish')}" if failed_ending else
                        f"our free model closed the stream after {seconds}s, before its finish token; automatic recovery was not safe"
                        if (delivered or outcome.get("sawToolCall") is True) else
                        "our free model closed the stream before its finish token, without answering; retrying"
                    )
                    record(False, outcome, {"truncated": True})
                    finish_turn(False, False, attempt + 1)
                    yield {"type": "usage", "usage": total_usage}
                    yield {"type": "finish", "reason": {"kind": "error", "failure": {"message": message, "code": code}}}
                    return
                if (outcome.get("sawText") is not True and outcome.get("sawToolCall") is not True
                        and outcome.get("sawReasoning") is not True and reason["kind"] == "stop"):
                    record(False, outcome)
                    finish_turn(False, False, attempt + 1)
                    yield {"type": "usage", "usage": total_usage}
                    yield {"type": "finish", "reason": {"kind": "error", "failure": {"message": "our free model returned an empty response", "code": CODE["empty"]}}}
                    return
                record(True, outcome, {"recovered": reason["kind"] == "stop"} if recovering else {})
                finish_turn(True, recovering and reason["kind"] == "stop", attempt + 1)
                yield {"type": "usage", "usage": total_usage}
                yield {"type": "finish", "reason": reason}
                if warnings:
                    deps["warn"](f"our-free-model: dropped unsupported content for {entry['id']}: {', '.join(warnings)}")
                return
            except BaseException as error:  # noqa: BLE001
                if isinstance(error, asyncio.CancelledError):
                    raise
                if isinstance(error, UpstreamError) and error.code == CODE["region"]:
                    deps["onRegionBlocked"](entry["id"])
                aborted = abort_event is not None and abort_event.is_set()
                failure = to_failure(error)
                if not aborted and (recovering or expired["value"]):
                    failure = {
                        **failure,
                        "code": "STREAM_CUT" if (recovering or delivered or (partial_outcome or {}).get("sawToolCall") is True) else CODE["timeout"],
                        "message": f"our free model reached its {round(timeout_ms/1000)}s time limit before its finish token"
                                   + (", during the continuation from its checkpoint" if recovering else "")
                                   if expired["value"] else f"our free model continuation failed: {failure['message']}",
                    }
                if not usage_added:
                    total_usage = add_usage(total_usage, (partial_outcome or {}).get("usage"), (partial_outcome or {}).get("sawUsage") is True)
                record(False, partial_outcome, {**({"truncated": True} if (recovering or expired["value"]) else {}),
                                                **({"aborted": True} if aborted else {})})
                finish_turn(False, False, attempt + 1)
                for chunk in blocks["close"]():
                    yield chunk
                if recovering or (partial_outcome or {}).get("sawUsage") is True:
                    yield {"type": "usage", "usage": total_usage}
                yield {"type": "finish", "reason": {"kind": "aborted" if aborted else "error", "failure": failure}}
                return
            finally:
                if watchdog_task is not None:
                    watchdog_task.cancel()
                if not task.done():
                    task.cancel()
                try:
                    await task
                except BaseException:  # noqa: BLE001
                    pass
                if not recorded:
                    record(False, partial_outcome, {"aborted": True})
                if not continuation_scheduled and not turn_recorded:
                    finish_turn(False, False, attempt + 1)


def JSON_ONLY(extra: dict) -> dict:
    return {k: v for k, v in extra.items()}


def apply_sealed_pacing_hint(payload: dict) -> None:
    if isinstance(payload.get("messages"), list):
        system = next((m for m in payload["messages"] if isinstance(m, dict) and m.get("role") == "system"
                       and isinstance(m.get("content"), str)), None)
        if system is not None:
            system["content"] = SEALED_PACING_HINT if system["content"] == "" else f"{system['content']}\n\n{SEALED_PACING_HINT}"
            return
        payload["messages"].insert(0, {"role": "system", "content": SEALED_PACING_HINT})
        return
    if isinstance(payload.get("system"), str):
        payload["system"] = SEALED_PACING_HINT if payload["system"] == "" else f"{payload['system']}\n\n{SEALED_PACING_HINT}"


def build_payload(wire: str, model_id: str, messages: list[dict], options: dict, budget: int,
                  resolve_image, warnings: list) -> dict:
    if wire == "responses":
        inp = to_response_input(messages, resolve_image, warnings)
        return {"model": model_id,
                "input": inp if inp else [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "..."}]}],
                "stream": True, "store": False, "max_output_tokens": budget}
    if wire == "messages":
        shaped = to_claude_messages(messages, resolve_image, warnings)
        payload = {"model": model_id, "messages": shaped["messages"], "stream": True, "max_tokens": budget}
        if shaped.get("system") is not None:
            payload["system"] = shaped["system"]
        return payload
    chat = to_chat_messages(messages, resolve_image, warnings)
    system = options.get("system")
    return {"model": model_id,
            "messages": ([{"role": "system", "content": system}, *chat] if isinstance(system, str) and system != "" else chat),
            "stream": True, "max_tokens": budget}


def to_failure(error) -> dict:
    if isinstance(error, UpstreamError):
        message = error.message or str(error)
        code = error.code or CODE["transport"]
        status = getattr(error, "status", None)
        retry_after = getattr(error, "providerRetryAfterMs", None)
    else:
        message = str(error) or "our free model request failed"
        code = CODE["transport"]
        status = None
        retry_after = None
    out = {"message": message, "code": code}
    if isinstance(status, int) and 100 <= status <= 599:
        out["status"] = status
    if isinstance(retry_after, (int, float)) and retry_after > 0:
        out["providerRetryAfterMs"] = int(retry_after)
    return out


def describe(entry: dict, settings: dict | None) -> str:
    parts = ["vision + text input" if entry.get("vision") else "text input",
             f"{round((entry.get('contextWindow') or 0) / 1024)}K context"]
    if entry.get("reasoning") is True:
        if isinstance(entry.get("efforts"), list) and entry["efforts"]:
            parts.append(f"thinking levels: {' / '.join(entry['efforts'])}")
        else:
            rung = round(budget_for(DEFAULT_LEVEL, entry, None, (settings or {}).get("defaultMaxTokens")) / 1024)
            parts.append(f"thinking always on · {rung}K default ceiling, shared with the answer"
                         if entry.get("canDisableThinking") is False else "tunable thinking budget")
    return " · ".join(parts)
