"""单生产者 / 单消费者异步通道。

把回调源（SSE 读取器每次调用交回一个负载）桥接到异步迭代消费方（分块解析器）。
``push`` 从不阻塞生产者：未被领取的值排队。

本移植用 asyncio.Future 唤醒等待中的消费者，替代原版的 waiting 数组。
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator


class Channel:
    def __init__(self) -> None:
        self._queue: list[Any] = []
        self._waiter: asyncio.Future | None = None
        self._ended = False

    def push(self, value: Any) -> None:
        """负载；``None`` 结束；``BaseException`` 失败。"""
        if self._ended:
            return
        if self._waiter is not None and not self._waiter.done():
            waiter, self._waiter = self._waiter, None
            waiter.set_result(value)
        else:
            self._queue.append(value)
        if value is None or isinstance(value, BaseException):
            self._ended = True

    async def read(self) -> AsyncIterator[str]:
        while True:
            if self._queue:
                value = self._queue.pop(0)
            else:
                self._waiter = asyncio.get_event_loop().create_future()
                value = await self._waiter
                self._waiter = None
            if isinstance(value, BaseException):
                raise value
            if value is None:
                return
            yield value


def create_channel() -> Channel:
    return Channel()
