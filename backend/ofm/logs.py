"""请求日志：每次转发的调用记录（含失败原因），供控制台「日志」页查看。

- 内存里保留最近 :data:`LOG_LIMIT` 条（新的在前），保证读取极快；
- 同时以 **JSONL 追加** 落到 ``<数据目录>/logs.jsonl``：追加廉价、崩溃安全，
  启动时读取尾部并重写一次以裁剪体积；
- 请求/响应只保留**截断预览**（:data:`PREVIEW_CHARS`），避免日志被长文本撑爆。
"""

from __future__ import annotations

import json
import os
from collections import deque
from typing import Any

LOG_LIMIT = 500
PREVIEW_CHARS = 2000


def preview(value: Any, limit: int = PREVIEW_CHARS) -> str:
    """把任意值变成可放进日志的短文本。"""
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = text.strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…（已截断，共 {len(text)} 字符）"


class RequestLog:
    def __init__(self, data_dir: str, limit: int = LOG_LIMIT):
        self.limit = limit
        self.file = os.path.join(data_dir, "logs.jsonl")
        self._items: deque[dict] = deque(maxlen=limit)
        self._next_id = 1
        self._load()

    # ── 落盘 ────────────────────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            with open(self.file, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except (OSError, ValueError):
            return
        for line in lines[-self.limit:]:
            if line.strip() == "":
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                self._items.append(record)
                self._next_id = max(self._next_id, int(record.get("id") or 0) + 1)
        self._rewrite()

    def _append(self, record: dict) -> None:
        try:
            os.makedirs(os.path.dirname(self.file), exist_ok=True)
            with open(self.file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _rewrite(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.file), exist_ok=True)
            temp = f"{self.file}.{os.getpid()}.tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                for record in self._items:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            os.replace(temp, self.file)
        except OSError:
            pass

    # ── 读写 ────────────────────────────────────────────────────────────────
    def add(self, record: dict) -> dict:
        item = {**record, "id": self._next_id}
        self._next_id += 1
        self._items.append(item)
        self._append(item)
        return item

    def list(self, *, model: str | None = None, errors_only: bool = False,
             limit: int = 100, offset: int = 0) -> dict:
        rows = list(reversed(self._items))
        if model:
            rows = [r for r in rows if r.get("model") == model]
        if errors_only:
            rows = [r for r in rows if r.get("ok") is not True]
        total = len(rows)
        # 列表不带预览（体积大），详情接口再取。
        page = [{k: v for k, v in r.items() if k not in ("request", "response")} for r in rows[offset:offset + limit]]
        seen: dict[str, int] = {}
        for r in self._items:
            key = r.get("model") or ""
            seen[key] = seen.get(key, 0) + 1
        return {
            "items": page, "total": total, "limit": self.limit,
            "stored": len(self._items),
            "failed": sum(1 for r in self._items if r.get("ok") is not True),
            "models": [{"id": k, "count": v} for k, v in sorted(seen.items(), key=lambda kv: -kv[1])],
        }

    def get(self, record_id: int) -> dict | None:
        for record in reversed(self._items):
            if record.get("id") == record_id:
                return record
        return None

    def clear(self) -> None:
        self._items.clear()
        try:
            os.remove(self.file)
        except OSError:
            pass
