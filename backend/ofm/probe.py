"""可用性探测与出口检测。

网关不披露哪些模型在当前出口可用：模型清单只是扁平 id 列表，
排除只在请求被 ``RegionError`` 拒绝时才出现。故可用性通过「提问」建立。
"""

from __future__ import annotations

import asyncio
import json
import re
import time

from .http_client import CODE, UpstreamError, post_streamed
from .upstream import endpoint_for, mint_request_id, session_for_conversation, wire_for, apply_fingerprint
from . import http_client

ECHO_SOURCES = [
    {"url": "https://api.ipify.org?format=json", "pick": lambda p: p.get("ip"), "extra": None},
    {"url": "https://ipinfo.io/json", "pick": lambda p: p.get("ip"), "extra": lambda p: p.get("country")},
    {"url": "https://ipapi.co/json/", "pick": lambda p: p.get("ip"), "extra": lambda p: p.get("country_code")},
]

STATE = {
    "available": "available",
    "regionBlocked": "region-blocked",
    "unavailable": "unavailable",
    "throttled": "throttled",
    "unknown": "unknown",
}

PING_PROMPT = "ping"
ROUTING_REFUSAL_STATUS = {400, 404, 422}


def _build_ping(model_id: str, wire: str) -> dict:
    if wire == "responses":
        return {"model": model_id, "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": PING_PROMPT}]}],
                "stream": True, "store": False, "max_output_tokens": 16}
    if wire == "messages":
        return {"model": model_id, "messages": [{"role": "user", "content": PING_PROMPT}], "stream": True, "max_tokens": 16}
    return {"model": model_id, "messages": [{"role": "user", "content": PING_PROMPT}], "stream": True, "max_tokens": 16}


async def probe_model(model: dict, attribution_user_agent: str | None = None, timeout_ms: int = 45000) -> dict:
    started = time.time() * 1000
    session = session_for_conversation("probe:our-free-model")
    wire = wire_for(model["id"])
    body = _build_ping(model["id"], wire)
    apply_fingerprint(body, wire == "responses")

    first_delta = None
    stream_error = None

    def on_data(payload: str) -> None:
        nonlocal first_delta, stream_error
        if stream_error is None and re.search(r'"(?:type"\s*:\s*"error"|"error"\s*:)', payload):
            try:
                parsed = json.loads(payload)
                failure = parsed.get("error") or (parsed if parsed.get("type") == "error" else None)
                if failure is not None:
                    stream_error = failure.get("message") if isinstance(failure.get("message"), str) else "upstream error"
                    return
            except ValueError:
                pass
        if first_delta is not None:
            return
        if re.search(r'"(delta|content|text|output_item)"|response\.(output_item|output_text|function_call)', payload):
            first_delta = time.time() * 1000

    try:
        await post_streamed(endpoint_for(model["id"]), body, session, mint_request_id(),
                            attribution_user_agent, on_data, timeout_ms)
        if stream_error is not None:
            return {"state": STATE["unknown"], "detail": stream_error[:200], "latencyMs": time.time() * 1000 - started}
        return {"state": STATE["available"], "latencyMs": time.time() * 1000 - started,
                "ttftMs": None if first_delta is None else first_delta - started}
    except UpstreamError as error:
        return {"state": _state_of(error), "detail": (error.message or str(error))[:200],
                "latencyMs": time.time() * 1000 - started}
    except BaseException as error:  # noqa: BLE001
        return {"state": STATE["unknown"], "detail": str(error)[:200], "latencyMs": time.time() * 1000 - started}


def _state_of(error: UpstreamError) -> str:
    if error.code == CODE["region"]:
        return STATE["regionBlocked"]
    if error.code == CODE["quota"]:
        return STATE["throttled"]
    message = str(error.message or "")
    status = getattr(error, "status", None)
    gateway_trouble = isinstance(status, int) and status >= 500
    named = getattr(error, "unavailable", False) is True or (
        not gateway_trouble and re.search(r"unavailable|not supported|no such model|unknown model|invalid model", message, re.IGNORECASE))
    if named:
        return STATE["unavailable"]
    if isinstance(status, int) and status in ROUTING_REFUSAL_STATUS:
        return STATE["unavailable"]
    return STATE["unknown"]


async def detect_egress(timeout_ms: int = 8000):
    """解析网关看到的公网地址及其国家码。失败即返回 None（不阻塞）。"""
    client = await http_client.get_client()
    for source in ECHO_SOURCES:
        try:
            response = await client.get(source["url"], headers={"accept": "application/json"}, timeout=timeout_ms / 1000.0)
            if response.status_code >= 400:
                continue
            payload = response.json()
            ip = source["pick"](payload)
            if not isinstance(ip, str) or ip == "":
                continue
            country = source["extra"](payload) if source["extra"] else None
            return {"ip": ip, **({} if country is None else {"country": str(country)})}
        except Exception:
            continue
    return None


async def probe_catalog(models: list[dict], attribution_user_agent: str | None = None,
                        on_result=None, concurrency: int = 2, timeout_ms: int = 45000) -> dict:
    """以有界并发探测整个目录。"""
    results: dict[str, dict] = {}
    cursor = {"value": 0}
    lock = asyncio.Lock()

    async def worker():
        while True:
            async with lock:
                if cursor["value"] >= len(models):
                    return
                index = cursor["value"]
                cursor["value"] += 1
            model = models[index]
            result = await probe_model(model, attribution_user_agent, timeout_ms)
            results[model["id"]] = result
            if on_result is not None:
                on_result(model["id"], result)

    workers = [asyncio.create_task(worker()) for _ in range(max(1, min(concurrency, len(models))))]
    if workers:
        await asyncio.gather(*workers)
    return results
