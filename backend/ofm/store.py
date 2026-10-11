"""持久化状态：设置、用量统计、探测结果、目录缓存。

存储为普通 JSON 文件（与宿主无关）。写入经过「临时文件 + 重命名」，
崩溃不会留下截断文件；写入按 800ms 合并，避免每个 token 样本都落盘。
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable

STATS_VERSION = 3


def day_key(at_ms: float | None = None) -> str:
    """本机日历的 ``YYYY-MM-DD``。"""
    t = time.localtime((at_ms / 1000.0) if at_ms is not None else time.time())
    return f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}"


SETTINGS_INITIAL: dict[str, Any] = {
    "version": 1,
    # 总开关：关闭后路由仍在，但不服务任何内容。
    "enabled": True,
    # 在选择器中展示地区受限模型。
    "exposeRegionModels": True,
    # 后台可用性重新探测的间隔（分钟）。
    "probeIntervalMinutes": 15,
    # 本地 OpenAI 兼容转发口。
    "forward": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 18900,
        # 局域网第二道门，独立密钥。
        "lan": {"enabled": False, "port": 0},
    },
    # 出口代理（订阅或单个客户端）。
    "egress": {"enabled": False, "mode": "client", "url": "", "mihomoPath": ""},
    # 单轮输出上限。
    "defaultMaxTokens": 32768,
    # 允许一次纯推理检查点续写。
    "streamRecovery": True,
    # 本地转发的 API Key（首次启动生成）。
    "forwardKey": "",
    "forwardLanKey": "",
    # 目录最近同步时间。
    "catalogSyncedAt": 0,
    "announcementAck": "",
    "notifyOs": False,
    "reloadCount": 0,
}

STATS_INITIAL: dict[str, Any] = {
    "version": STATS_VERSION,
    "days": {},
    "models": {},
    "requests": 0,
    "failedRequests": 0,
    "samples": [],
    "logical": {"turns": 0, "failed": 0, "recovered": 0, "models": {}},
}

AVAILABILITY_INITIAL: dict[str, Any] = {"version": 1, "at": 0, "egress": None, "results": {}}


class JsonStore:
    """带合并写入的 JSON 状态文件。线程安全。"""

    def __init__(self, file: str, initial: dict[str, Any]):
        self.file = file
        self._value = json.loads(json.dumps(initial))
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._dirty = False
        self._disposed = False
        self._load()

    def _load(self) -> None:
        try:
            with open(self.file, "r", encoding="utf-8") as handle:
                parsed = json.load(handle)
            if isinstance(parsed, dict):
                self._value.update(parsed)
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, OSError):
            # 损坏文件先备份，避免下次写入直接覆盖用户数据。
            try:
                if os.path.exists(self.file):
                    os.replace(self.file, f"{self.file}.corrupt-{int(time.time() * 1000)}")
            except OSError:
                pass

    def get(self) -> dict[str, Any]:
        return self._value

    def update(self, patch: dict[str, Any]) -> dict[str, Any]:
        if self._disposed:
            return self._value
        with self._lock:
            self._value.update(patch)
        self._schedule()
        return self._value

    def edit(self, mutate: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
        if self._disposed:
            return self._value
        with self._lock:
            clone = json.loads(json.dumps(self._value))
            next_value = mutate(clone)
            if next_value is not None:
                self._value = next_value
        self._schedule()
        return self._value

    def _schedule(self, delay: float = 0.8) -> None:
        if self._disposed:
            return
        self._dirty = True
        with self._lock:
            if self._timer is not None:
                return
            timer = threading.Timer(delay, self.flush)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def flush(self) -> None:
        with self._lock:
            self._timer = None
            if not self._dirty or self._disposed:
                return
            self._dirty = False
        try:
            directory = os.path.dirname(self.file)
            if directory:
                os.makedirs(directory, exist_ok=True)
            temp = f"{self.file}.{os.getpid()}.tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(self._value, handle, ensure_ascii=False, indent=2)
            os.replace(temp, self.file)
        except OSError:
            with self._lock:
                self._dirty = True

    def dispose(self) -> None:
        self.flush()
        self._disposed = True
        self._dirty = False


# ── 用量统计 ────────────────────────────────────────────────────────────────

MIN_DECODE_MS = 250
MAX_CREDIBLE_TPS = 250


def decode_window(decode_ms: float, tokens: float, ok: bool) -> dict[str, Any]:
    """判定一次调用的解码窗口是否可测量。"""
    ms = decode_ms if isinstance(decode_ms, (int, float)) and decode_ms > 0 else 0
    count = tokens if isinstance(tokens, (int, float)) else 0
    if ok is not True or count <= 0 or ms < MIN_DECODE_MS:
        return {"measurable": False, "decodeMs": 0, "tps": None}
    tps = (count / ms) * 1000
    if tps != tps or tps > MAX_CREDIBLE_TPS:
        return {"measurable": False, "decodeMs": 0, "tps": None}
    return {"measurable": True, "decodeMs": ms, "tps": round(tps)}


def record_usage(stats: JsonStore, record: dict[str, Any]) -> None:
    def apply(state: dict[str, Any]) -> dict[str, Any]:
        day = day_key(record.get("at"))
        days = dict(state.get("days") or {})
        bucket = dict(days.get(day) or {"total": 0, "models": {}})
        per_model = dict(bucket.get("models") or {})
        previous = per_model.get(record["model"]) or {
            "input": 0, "output": 0, "reasoning": 0, "cacheRead": 0, "calls": 0, "failed": 0,
            "ttftMs": 0, "ttftSamples": 0, "decodeMs": 0, "decodeTokens": 0,
        }
        measured = decode_window(record.get("decodeMs", 0), record.get("decodeTokens", 0), record.get("ok") is True)
        ttft = record.get("ttftMs")
        ttft_ms = ttft if isinstance(ttft, (int, float)) and record.get("ok") is True else None
        per_model[record["model"]] = {
            "input": previous["input"] + record.get("input", 0),
            "output": previous["output"] + record.get("output", 0),
            "reasoning": previous["reasoning"] + record.get("reasoning", 0),
            "cacheRead": previous["cacheRead"] + record.get("cacheRead", 0),
            "calls": previous["calls"] + 1,
            "failed": previous["failed"] + (0 if record.get("ok") else 1),
            "ttftMs": previous["ttftMs"] + (ttft_ms or 0),
            "ttftSamples": previous["ttftSamples"] + (0 if ttft_ms is None else 1),
            "decodeMs": previous["decodeMs"] + measured["decodeMs"],
            "decodeTokens": previous["decodeTokens"] + (record.get("decodeTokens", 0) if measured["measurable"] else 0),
        }
        days[day] = {**bucket, "models": per_model, "total": bucket["total"] + record.get("input", 0) + record.get("output", 0)}

        models = dict(state.get("models") or {})
        lifetime = models.get(record["model"]) or {"input": 0, "output": 0, "reasoning": 0, "cacheRead": 0, "calls": 0, "failed": 0}
        models[record["model"]] = {
            "input": lifetime.get("input", 0) + record.get("input", 0),
            "output": lifetime.get("output", 0) + record.get("output", 0),
            "reasoning": lifetime.get("reasoning", 0) + record.get("reasoning", 0),
            "cacheRead": lifetime.get("cacheRead", 0) + record.get("cacheRead", 0),
            "calls": lifetime.get("calls", 0) + 1,
            "failed": lifetime.get("failed", 0) + (0 if record.get("ok") is True else 1),
        }
        sample = {
            "at": record.get("at"), "model": record.get("model"), "ok": record.get("ok") is True,
            "input": record.get("input", 0), "output": record.get("output", 0),
            "ttftMs": None if ttft_ms is None else round(ttft_ms),
            "tps": measured["tps"], "decodeMs": measured["decodeMs"],
            "decodeTokens": record.get("decodeTokens", 0) if measured["measurable"] else 0,
            "effort": record.get("effort", ""), "origin": record.get("origin", "chat"),
        }
        for flag in ("truncated", "noUsage", "recoveryAttempt", "recoveryScheduled", "recovered", "aborted"):
            if record.get(flag) is True:
                sample[flag] = True
        for key in ("recoveryId", "attempt", "elapsedMs"):
            if record.get(key) is not None:
                sample[key] = record[key]
        samples = (list(state.get("samples") or []) + [sample])[-400:]
        return {
            **state, "days": days, "models": models,
            "requests": (state.get("requests") or 0) + 1,
            "failedRequests": (state.get("failedRequests") or 0) + (0 if record.get("ok") is True else 1),
            "samples": samples,
        }

    stats.edit(apply)


def record_turn(stats: JsonStore, record: dict[str, Any]) -> None:
    def apply(state: dict[str, Any]) -> dict[str, Any]:
        previous = state.get("logical") or {}
        models = dict(previous.get("models") or {})
        row = models.get(record["model"]) or {"turns": 0, "failed": 0, "recovered": 0}
        failed = 0 if record.get("ok") is True else 1
        recovered = 1 if record.get("recovered") is True else 0
        models[record["model"]] = {
            "turns": row["turns"] + 1,
            "failed": row["failed"] + failed,
            "recovered": row["recovered"] + recovered,
        }
        return {
            **state,
            "logical": {
                **previous,
                "turns": (previous.get("turns") or 0) + 1,
                "failed": (previous.get("failed") or 0) + failed,
                "recovered": (previous.get("recovered") or 0) + recovered,
                "models": models,
            },
        }

    stats.edit(apply)


def prune_days(state: dict[str, Any], keep_days: int = 120) -> dict[str, Any]:
    keys = sorted((state.get("days") or {}).keys())
    if len(keys) <= keep_days:
        return state
    drop = set(keys[: len(keys) - keep_days])
    days = {key: value for key, value in (state.get("days") or {}).items() if key not in drop}
    return {**state, "days": days}


def migrate_stats(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("version") == STATS_VERSION:
        return value
    # 旧版本统计迁移：保守处理，重置速度派生量。
    version = value.get("version")
    version = version if isinstance(version, int) else 0
    reset_speed = version < 2
    days: dict[str, Any] = {}
    for day, bucket in (value.get("days") or {}).items():
        models = {}
        for model, row in (bucket.get("models") or {}).items():
            models[model] = {**row, "decodeMs": 0, "decodeTokens": 0, "ttftMs": 0, "ttftSamples": 0} if reset_speed else {**row}
        days[day] = {**bucket, "models": models}
    return {**value, "version": STATS_VERSION, "days": days, "samples": value.get("samples") or [], "logical": value.get("logical") or {"turns": 0, "failed": 0, "recovered": 0, "models": {}}}
