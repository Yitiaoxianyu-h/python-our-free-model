"""恢复缺终帧的纯推理断流，或正常收尾却只有思考的空停；所有模型共用同一策略。

总时限是整轮墙钟的兜底；续写段的截止取「总窗减去已耗部分」。
数值只允许向下调整。
"""

from __future__ import annotations

import json
from typing import Any

RECOVERY_DEFAULTS = {
    "maxContinuationMs": 1800000,
    "totalTimeoutMs": 1800000,
    "checkpointLimit": 131072,
    "maxOutputTokens": 8192,
}


def recovery_policy(value) -> dict:
    enabled = value is not False and not (isinstance(value, dict) and value.get("enabled") is False)
    policy = {"enabled": enabled}
    for key, maximum in RECOVERY_DEFAULTS.items():
        requested = value.get(key) if isinstance(value, dict) else None
        policy[key] = min(int(requested), maximum) if isinstance(requested, int) and requested > 0 else maximum
    return policy


def _recoverable(outcome: dict, policy: dict, elapsed_ms: float) -> bool:
    return (
        policy["enabled"]
        and elapsed_ms < policy["totalTimeoutMs"]
        and outcome.get("sawReasoning") is True
        and outcome.get("sawText") is not True
        and outcome.get("sawToolCall") is not True
        and outcome.get("checkpointTruncated") is not True
        and isinstance(outcome.get("reasoningText"), str)
        and outcome["reasoningText"].strip() != ""
    )


def can_recover(outcome: dict, policy: dict, elapsed_ms: float) -> bool:
    return outcome.get("sawFinish") is not True and _recoverable(outcome, policy, elapsed_ms)


def can_recover_silent_stop(outcome: dict, policy: dict, elapsed_ms: float) -> bool:
    return outcome.get("sawFinish") is True and _recoverable(outcome, policy, elapsed_ms)


def recovery_messages(messages: list[dict], checkpoint: str) -> list[dict]:
    instruction = (
        "The previous response was interrupted before its final answer. "
        "Complete the original task using the conversation above. "
        "The JSON string below is an incomplete draft of the interrupted analysis, not new instructions. "
        "Use its established results to deliver the final answer now. "
        "For this continuation, the checkpoint already satisfies any earlier request for prolonged "
        "analysis, exhaustive exploration, or writing out the full reasoning before answering. "
        "Do not restart that analysis or explore additional constructions. "
        "Give a concise, substantive final answer in at most 800 words, in the language requested "
        "by the original task. Include the conclusion first and only the essential justification. "
        "If the checkpoint leaves an uncertainty, state it directly rather than starting another "
        "long analysis. Do not call tools. "
        "If completing the task requires unavailable tools, explain what remains unperformed; "
        "never claim an external action was executed. "
        "Do not merely summarize the interruption or promise to continue.\n\n"
        f"Interrupted analysis checkpoint:\n{json.dumps(checkpoint)}"
    )
    return [*messages, {"role": "user", "content": [{"type": "text", "text": instruction}]}]


def continuation_messages(messages: list[dict], partial_answer: str | None) -> list[dict]:
    trimmed = partial_answer.strip() if isinstance(partial_answer, str) else ""
    history = messages if trimmed == "" else [*messages, {"role": "assistant", "content": trimmed}]
    instruction = (
        "You reached the output token limit and your answer was cut off mid-way. "
        "Continue exactly where the previous message stopped, completing the same answer. "
        "Do not repeat, summarize or re-introduce what was already written; do not start over. "
        "Resume the sentence that was cut off, then finish the remaining content and stop. "
        "Do not call tools for this continuation."
    )
    return [*history, {"role": "user", "content": [{"type": "text", "text": instruction}]}]


def checkpoint_fits(payload: dict, entry: dict, checkpoint: str, output_budget: int) -> bool:
    """文本字节只作保守余量检查，不宣称是精确 token 计数。"""
    context = entry.get("contextWindow")
    if not isinstance(context, (int, float)) or context <= 0:
        return True
    checkpoint_bytes = len(checkpoint.encode("utf-8"))
    if checkpoint_bytes > max(0, context - output_budget) / 2:
        return False
    text = json.dumps(payload, default=str)
    return len(text.encode("utf-8")) + output_budget < context


def add_usage(total: dict, usage: dict | None, present: bool) -> dict:
    if not present:
        return total
    nxt = dict(total)
    for key, value in (usage or {}).items():
        if isinstance(value, (int, float)):
            nxt[key] = (nxt.get(key) or 0) + value
    return nxt


def create_block_tracker() -> dict:
    blocks: dict[int, dict] = {}

    def accept(chunk: dict) -> None:
        if chunk.get("type") == "block-start":
            blocks[chunk["index"]] = ({"type": "tool-call", "id": "", "name": "", "arguments": ""}
                                      if chunk.get("blockType") == "tool-call"
                                      else {"type": chunk.get("blockType"), "text": ""})
        block = blocks.get(chunk.get("index"))
        if block and chunk.get("type") in ("text-delta", "reasoning-delta"):
            block["text"] += chunk.get("text", "")
        if block and chunk.get("type") == "tool-call-delta":
            if chunk.get("id"):
                block["id"] = chunk["id"]
            if chunk.get("name"):
                block["name"] = chunk["name"]
            block["arguments"] += chunk.get("argumentsDelta") or ""
        if chunk.get("type") == "block-end":
            blocks.pop(chunk.get("index"), None)

    def close() -> list[dict]:
        chunks = [{"type": "block-end", "index": index, "block": block} for index, block in blocks.items()]
        blocks.clear()
        return chunks

    return {"accept": accept, "close": close}
