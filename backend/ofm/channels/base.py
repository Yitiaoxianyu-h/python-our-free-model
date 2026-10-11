"""渠道适配器基类与 OpenAI 兼容渠道实现。"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import read_stream


@dataclass
class ChannelProvider:
    """一个渠道的静态元数据。"""

    id: str
    name: str
    vendor: str
    login: str = "pending"          # browser / device-code / sms / captcha / none / pending
    domains: list[str] = field(default_factory=list)
    implemented: bool = False


class OpenAICompatChannel:
    """标准 OpenAI 兼容上游的流式适配器。

    多数账号渠道的推理端点是 OpenAI 兼容的（区别只在鉴权头与 base URL），
    故这一实现可被多家复用；差异收敛到构造参数。
    """

    def __init__(self, *, provider_id: str, base_url: str, auth_header: str = "authorization",
                 auth_prefix: str = "Bearer ", extra_headers: dict[str, str] | None = None):
        self.provider_id = provider_id
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.auth_prefix = auth_prefix
        self.extra_headers = extra_headers or {}

    def _headers(self, credential: str) -> dict[str, str]:
        headers = {
            "content-type": "application/json",
            "accept": "text/event-stream",
            **self.extra_headers,
        }
        if credential:
            headers[self.auth_header] = f"{self.auth_prefix}{credential}" if self.auth_prefix else credential
        return headers

    async def stream(self, body: dict, credential: str) -> AsyncIterator[dict]:
        """POST 一轮并产出内部 chunk。"""
        channel = create_channel()
        client = await get_client()

        async def produce():
            try:
                async with client.stream("POST", f"{self.base_url}/chat/completions",
                                         headers=self._headers(credential), content=json.dumps(body),
                                         timeout=httpx.Timeout(connect=15.0, read=300.0, write=60.0, pool=15.0)) as response:
                    if response.status_code >= 400:
                        text = (await response.aread()).decode("utf-8", "replace")
                        raise UpstreamError(f"{self.provider_id}: HTTP {response.status_code} {text[:200]}", CODE["server"],
                                            status=response.status_code)
                    head = await read_head(response.aiter_bytes(), 4096, 300.0)
                    shape = sniff_body(head.text)
                    if shape == "empty":
                        raise UpstreamError(f"{self.provider_id}: empty response", CODE["empty"])
                    if shape == "sse":
                        await read_sse(_replay(head), channel.push, 300.0)
                    else:
                        text = (await _read_remainder(head)).decode("utf-8", "replace")
                        try:
                            payload = json.loads(text)
                        except ValueError:
                            raise UpstreamError(f"{self.provider_id}: unexpected non-stream response", CODE["server"])
                        channel.push(json.dumps(payload))
                channel.push(None)
            except BaseException as error:  # noqa: BLE001
                channel.push(error if isinstance(error, BaseException) else RuntimeError(str(error)))

        task = asyncio.create_task(produce())
        reader = read_stream(channel.read(), "chat", None, None)
        try:
            while True:
                done, value = await reader.next()
                if done:
                    return
                yield value
        finally:
            await reader.close()
            if not task.done():
                task.cancel()
            try:
                await task
            except BaseException:  # noqa: BLE001
                pass
