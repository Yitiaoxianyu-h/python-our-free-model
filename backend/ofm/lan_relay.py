"""局域网转发中继：本机监听只绑回环，另开一扇门给同一网络中的其它设备。

与原版（``src/forward.js`` 的 ``startLanRelay``）语义一致：

- 独立监听地址（默认 ``0.0.0.0``）与**独立密钥**（``lanKey``），与本机 ``forwardKey`` 互不通用；
- **每个请求**都要带局域网 Key（连 ``/health`` 也不例外）；
- 仅放行 ``/v1/models``、``/v1/chat/completions``、``/v1/responses`` 三条白名单路径；
- 入口把局域网 Key 换成本机 Key，转发到 ``127.0.0.1:<本机端口>``；
- 带 ``x-ofm-relay-hop`` 的请求直接 508 拒绝，防止端口配成本机同一端口时自环。

本移植用 asyncio + uvicorn 在同进程内启动第二个监听器（不额外起进程）。
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

import httpx
import uvicorn

RELAY_PATHS = {
    "/v1/models", "/models",
    "/v1/chat/completions", "/chat/completions",
    "/v1/responses", "/responses",
}
HOP_HEADER = "x-ofm-relay-hop"

CORS_HEADERS = [
    (b"access-control-allow-origin", b"*"),
    (b"access-control-allow-headers", b"authorization, content-type, x-api-key"),
    (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
    (b"access-control-max-age", b"600"),
]


def _json(status: int, message: str) -> tuple[int, bytes, bytes]:
    body = ('{"error":{"message":"' + message + '","type":"invalid_request_error"}}').encode("utf-8")
    return status, b"application/json", body


def rank_lan_addresses() -> list[str]:
    """本机可供同网段其它设备拨通的 IPv4 地址，物理网卡优先。"""
    addresses: list[str] = []
    seen: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            address = info[4][0]
            if address in seen or address.startswith("127.") or address.startswith("169.254."):
                continue
            seen.add(address)
            addresses.append(address)
    except OSError:
        return []
    addresses.sort(key=lambda a: 0 if _is_private(a) else 1)
    return addresses


def _is_private(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


class LanRelay:
    def __init__(self, *, host: str, port: int, lan_key: str, local_port: int, local_key: str,
                 log=lambda message: None):
        self.host = host
        self.port = port
        self.lan_key = lan_key
        self.local_port = local_port
        self.local_key = local_key
        self.log = log
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None
        self.bound_port = 0

    async def start(self) -> int:
        # 自己先绑定端口：端口被占用时抛普通 OSError，而不是让 uvicorn 的
        # ``Server.startup`` 调 ``sys.exit(3)`` —— 那个 SystemExit 会冒到事件循环，
        # 把**整个进程**（含主服务）一起带走。这里必须先拿到 socket 再交给 uvicorn。
        # 刻意**不设** SO_REUSEADDR：Windows 上它会允许重复绑定同一端口，
        # 导致「端口被占用」检测不出来（两个监听器抢同一个端口）。
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((self.host, self.port))
            sock.listen(128)
            sock.setblocking(False)
        except OSError:
            sock.close()
            raise
        self.bound_port = sock.getsockname()[1]

        async def asgi_app(scope, receive, send):
            await self.handle(scope, receive, send)

        config = uvicorn.Config(asgi_app, log_level="warning", access_log=False, lifespan="off")
        self._server = uvicorn.Server(config)
        self._task = asyncio.create_task(self._server.serve(sockets=[sock]))
        for _ in range(100):
            if self._server.started:
                break
            await asyncio.sleep(0.05)
        return self.bound_port

    async def close(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                if self._task is not None:
                    self._task.cancel()
            self._task = None

    # ── ASGI ───────────────────────────────────────────────────────────────
    async def handle(self, scope: dict, receive, send) -> None:
        if scope["type"] != "http":
            return
        path = (scope.get("path") or "/").rstrip("/") or "/"
        method = scope.get("method", "GET")
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}

        if method == "OPTIONS":
            await send({"type": "http.response.start", "status": 204, "headers": CORS_HEADERS})
            await send({"type": "http.response.body", "body": b""})
            return

        if headers.get(HOP_HEADER) is not None:
            status, message = 508, "the LAN relay would be dialing itself - give it a port of its own"
        elif path not in RELAY_PATHS:
            status, message = 404, f"no route for {method} {path}"
        elif not self._authorized(headers.get("authorization", ""), headers.get("x-api-key", "")):
            status, message = 401, "missing or invalid LAN key"
        else:
            status, message = 0, ""

        if status != 0:
            code, content_type, body = _json(status, message)
            await send({"type": "http.response.start", "status": code,
                        "headers": [(b"content-type", content_type), *CORS_HEADERS]})
            await send({"type": "http.response.body", "body": body})
            return

        await self._proxy(scope, path, headers, receive, send)

    def _authorized(self, authorization: str, api_key: str) -> bool:
        if not self.lan_key:
            return False
        presented = authorization[7:].strip() if authorization.lower().startswith("bearer ") else api_key.strip()
        return bool(presented) and presented == self.lan_key

    async def _proxy(self, scope, path, headers, receive, send) -> None:
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        outgoing = {k: v for k, v in headers.items() if k not in ("host", "connection", "x-api-key", "authorization")}
        outgoing["authorization"] = f"Bearer {self.local_key}"
        outgoing[HOP_HEADER] = "1"
        query = scope.get("query_string", b"").decode("latin-1")
        url = f"http://127.0.0.1:{self.local_port}{path}" + (f"?{query}" if query else "")
        client = httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=600.0, write=60.0, pool=10.0))
        try:
            async with client.stream(scope["method"], url, headers=outgoing, content=body) as response:
                out_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in response.headers.items()
                               if k.lower() not in ("connection", "keep-alive", "transfer-encoding")]
                await send({"type": "http.response.start", "status": response.status_code,
                            "headers": [*out_headers, *CORS_HEADERS]})
                async for chunk in response.aiter_raw():
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        except Exception as error:  # noqa: BLE001
            self.log(f"lan relay upstream failed: {error}")
            code, content_type, payload = _json(502, "the local forward listener did not answer")
            await send({"type": "http.response.start", "status": code,
                        "headers": [(b"content-type", content_type), *CORS_HEADERS]})
            await send({"type": "http.response.body", "body": payload})
        finally:
            await client.aclose()
