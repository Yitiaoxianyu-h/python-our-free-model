"""FastAPI 应用：本地 OpenAI 兼容服务 + 网页管理 + 后台刷新/探测循环。

单一端口同时提供：
- ``/`` 网页控制台
- ``/api/management/*`` 同源管理接口（仅回环可达）
- ``/v1/models``、``/v1/chat/completions``、``/v1/responses``（Bearer API Key）
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import PRODUCT, __version__
from .completion import create_forward_completion, to_openai_usage
from .logs import RequestLog
from .forward import (
    HttpError,
    handle_chat_completions,
    handle_responses,
    json_response,
    openai_error,
)
from .lan_relay import LanRelay, rank_lan_addresses
from .paths import FRONTEND_DIR
from .runtime import create_model_runtime, create_runtime_stores
from .store import SETTINGS_INITIAL, record_usage as record_usage_stat

MAX_BODY_BYTES = 8 * 1024 * 1024


def generate_key() -> str:
    return f"ofm-{secrets.token_urlsafe(24)}"


def key_matches(presented: str | None, expected: str | None) -> bool:
    if not isinstance(presented, str) or not isinstance(expected, str):
        return False
    a, b = presented.encode(), expected.encode()
    if len(a) != len(b):
        return False
    return secrets.compare_digest(a, b)


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    key = request.headers.get("x-api-key")
    return key.strip() if isinstance(key, str) else ""


def _is_loopback(request: Request) -> bool:
    client = request.client.host if request.client else ""
    return client in ("127.0.0.1", "::1", "localhost", "")


class Service:
    def __init__(self, *, data_dir: str, host: str = "127.0.0.1", port: int = 18900,
                 refresh: bool = True, probe: bool = False):
        self.data_dir = data_dir
        self.host = host
        self.port = port
        self.do_refresh = refresh
        self.do_probe = probe
        self.stores = None
        self.runtime = None
        self.complete = None
        self.credentials = None
        self.pool = None
        self.channels = None
        self.relay = None
        self.logs = RequestLog(data_dir)
        self._tasks: list[asyncio.Task] = []
        self._closed = False
        self.app = self._build_app()

    # ── 生命周期 ────────────────────────────────────────────────────────────
    async def startup(self) -> None:
        self.stores = create_runtime_stores(self.data_dir)
        from .channels import AccountPool, ChannelManager, CredentialStore
        self.credentials = CredentialStore(self.data_dir)
        self.pool = AccountPool(self.data_dir)
        self.channels = ChannelManager(data_dir=self.data_dir, credentials=self.credentials,
                                       pool=self.pool, logger=self._log)
        settings = self.stores["settings"]
        if not settings.get().get("forwardKey"):
            settings.update({"forwardKey": generate_key()})
            settings.flush()
        if not settings.get().get("forwardLanKey"):
            settings.update({"forwardLanKey": generate_key()})
            settings.flush()

        def _sealed_credential_local():
            # 每次读取：EAC 页面保存网关配置后无需重启即可生效
            # （eac.py 内部有缓存，保存时会主动失效）。
            return self._sealed_credential()

        self.runtime = create_model_runtime(
            settings=self.stores["settings"], stats=self.stores["stats"],
            availability=self.stores["availability"], catalogStore=self.stores["catalogStore"],
            logger=self._log, attribution_user_agent="our-free-model",
            resolve_image=lambda ref: (ref or {}).get("url"),
            sealed_credential=_sealed_credential_local,
            channel_catalog=self.channels.catalog_entries,
            refresh_channels=self.channels.refresh_catalog,
        )
        self.complete = create_forward_completion(
            adapter=self.runtime["adapter"], state=self.runtime["state"],
            channel_stream=self.channels.stream,
            record_usage=lambda record: record_usage_stat(self.stores["stats"], record),
            record_log=self.logs.add,
        )

        if self.do_refresh:
            self._tasks.append(asyncio.create_task(self._boot_refresh()))
        if self.do_probe:
            self.stores["settings"].update({"probeIntervalMinutes": max(1, int(self.stores["settings"].get().get("probeIntervalMinutes") or 15))})
        self._tasks.append(asyncio.create_task(self._periodic_probe()))
        self._tasks.append(asyncio.create_task(self._periodic_egress()))
        self._tasks.append(asyncio.create_task(self._periodic_channels()))
        await self._sync_relay()
        self._log(f"service started on http://{self.host}:{self.port}")

    async def _sync_relay(self) -> None:
        """按设置启停局域网中继（第二道门，独立 Key）。"""
        settings = self.stores["settings"].get()
        forward = settings.get("forward") or {}
        lan = forward.get("lan") or {}
        wanted = lan.get("enabled") is True and forward.get("enabled") is not False
        port = int(lan.get("port") or 0)
        if self.relay is not None and wanted and self.relay.port == port:
            return
        if self.relay is not None:
            await self.relay.close()
            self.relay = None
        if not wanted:
            return
        if port and port == self.port:
            self._log("lan relay not started: it needs a port of its own")
            return
        relay = LanRelay(host=str(lan.get("host") or "0.0.0.0"), port=port,
                         lan_key=self.stores["settings"].get().get("forwardLanKey", ""),
                         local_port=self.port, local_key=self.stores["settings"].get().get("forwardKey", ""),
                         log=self._log)
        try:
            bound = await relay.start()
        except OSError as error:
            # 端口被占用（常见于同一台机器上还跑着另一个实例）。绝不因此让服务崩掉：
            # 先退到系统自动分配端口，仍失败就如实记录并继续提供本机转发口。
            if port != 0:
                self._log(f"lan relay: port {port} is unavailable ({error}); trying an auto-assigned port")
                relay = LanRelay(host=str(lan.get("host") or "0.0.0.0"), port=0,
                                 lan_key=self.stores["settings"].get().get("forwardLanKey", ""),
                                 local_port=self.port, local_key=self.stores["settings"].get().get("forwardKey", ""),
                                 log=self._log)
                try:
                    bound = await relay.start()
                except OSError as second:
                    self._log(f"lan relay could not start: {second}")
                    return
                self._log(f"lan relay is on an auto-assigned port {bound} (the configured {port} was taken)")
            else:
                self._log(f"lan relay could not start: {error}")
                return
        except Exception as error:  # noqa: BLE001
            self._log(f"lan relay could not start: {error}")
            return
        self.relay = relay
        if port == 0 and bound:
            forward = self.stores["settings"].get().get("forward") or {}
            lan = {**(forward.get("lan") or {}), "port": bound}
            self.stores["settings"].update({"forward": {**forward, "lan": lan}})
            self.stores["settings"].flush()
        self._log(f"lan relay listening on {relay.host}:{bound} (addresses: {', '.join(rank_lan_addresses()) or 'none'})")

    async def _boot_refresh(self) -> None:
        try:
            await self.runtime["refreshCatalog"](probe=bool(self.do_probe), force=True)
        except Exception as error:  # noqa: BLE001
            self._log(f"startup refresh failed ({error})")

    async def _periodic_probe(self) -> None:
        while not self._closed:
            period = max(1, int(self.stores["settings"].get().get("probeIntervalMinutes") or 15)) * 60
            await asyncio.sleep(period)
            if self._closed:
                return
            try:
                await self.runtime["watchEgress"]()
                await self.runtime["refreshCatalog"](probe=True)
            except Exception as error:  # noqa: BLE001
                self._log(f"periodic refresh failed ({error})")

    async def _periodic_egress(self) -> None:
        while not self._closed:
            await asyncio.sleep(120)
            if self._closed:
                return
            with contextlib.suppress(Exception):
                await self.runtime["watchEgress"]()

    async def _periodic_channels(self) -> None:
        """每 30 分钟刷新一次账号渠道的模型目录（与原版一致）。"""
        while not self._closed:
            await asyncio.sleep(30 * 60)
            if self._closed:
                return
            with contextlib.suppress(Exception):
                await self.channels.refresh_catalog()

    async def close(self) -> None:
        self._closed = True
        if self.relay is not None:
            with contextlib.suppress(Exception):
                await self.relay.close()
            self.relay = None
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(BaseException):
                await task
        if self.runtime is not None:
            self.runtime["dispose"]()
        if self.stores is not None:
            self.stores["dispose"]()
        from .http_client import close_client
        with contextlib.suppress(Exception):
            await close_client()

    def _log(self, message: str) -> None:
        print(f"[ofm] {message}", flush=True)

    # ── HTTP 路由 ───────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        @contextlib.asynccontextmanager
        async def lifespan(_app: FastAPI):
            await self.startup()
            try:
                yield
            finally:
                await self.close()

        app = FastAPI(title=PRODUCT, version=__version__, docs_url=None, redoc_url=None, lifespan=lifespan)

        @app.get("/health")
        async def health():
            return {"ok": True, "service": "our-free-model", "version": __version__}

        @app.get("/v1/models")
        async def models(request: Request):
            return await self._models(request)

        @app.post("/v1/chat/completions")
        async def chat(request: Request):
            gate = await self._v1_gate(request)
            if gate is not None:
                return gate
            return await handle_chat_completions(request, self.complete)

        @app.post("/v1/responses")
        async def responses(request: Request):
            gate = await self._v1_gate(request)
            if gate is not None:
                return gate
            return await handle_responses(request, self.complete)

        # ── 管理 API ────────────────────────────────────────────────────────
        @app.get("/api/management/summary")
        async def summary(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return self._summary()

        @app.get("/api/management/stats")
        async def stats(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return self._stats()

        @app.post("/api/management/settings")
        async def settings_post(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return await self._settings_post(request)

        @app.post("/api/management/refresh")
        async def refresh(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            await self.runtime["refreshCatalog"](probe=True, force=True)
            return self._summary()

        @app.post("/api/management/reprobe")
        async def reprobe(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            await self.runtime["refreshAvailability"](True)
            return self._summary()

        @app.get("/api/management/forward/key")
        async def forward_key(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return {"key": self.stores["settings"].get().get("forwardKey", ""), "port": self.port}

        @app.post("/api/management/forward/rotate")
        async def forward_rotate(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            minted = generate_key()
            self.stores["settings"].update({"forwardKey": minted})
            self.stores["settings"].flush()
            return {"key": minted}

        @app.get("/api/management/forward/lan")
        async def lan_status(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return self._settings_view()["forward"]["lan"]

        @app.get("/api/management/forward/lan/key")
        async def lan_key(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return {"key": self.stores["settings"].get().get("forwardLanKey", "")}

        @app.post("/api/management/forward/lan/rotate")
        async def lan_rotate(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            minted = generate_key()
            self.stores["settings"].update({"forwardLanKey": minted})
            self.stores["settings"].flush()
            await self._sync_relay()
            return {"key": minted}

        @app.get("/api/management/forward/lan/addresses")
        async def lan_addresses(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return {"addresses": rank_lan_addresses()}

        @app.get("/api/management/channels")
        async def channels(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            from .channels import list_channels
            rows = list_channels(self.pool)
            for row in rows:
                if row["implemented"] and row["id"] not in ("anonymous", "kilo"):
                    row["loginState"] = self.channels.login_result(row["id"])
            return {"channels": rows}

        @app.post("/api/management/channels/{channel_id}/login")
        async def channel_login(channel_id: str, request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return await self.channels.start_login(channel_id)

        @app.post("/api/management/channels/{channel_id}/login/submit")
        async def channel_login_submit(channel_id: str, request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return JSONResponse({"error": "invalid JSON body"}, status_code=400)
            return await self.channels.submit_login(channel_id, body if isinstance(body, dict) else {})

        @app.get("/api/management/channels/{channel_id}/login")
        async def channel_login_status(channel_id: str, request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return self.channels.login_result(channel_id)

        @app.get("/api/management/accounts")
        async def accounts(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            provider = request.query_params.get("provider")
            rows = []
            for account in self.pool.list_all():
                if provider and account.get("provider") != provider:
                    continue
                rows.append({
                    "id": account.get("id"), "provider": account.get("provider"),
                    "nickname": account.get("nickname"), "enabled": account.get("enabled") is not False,
                    "hasCredential": self.credentials.resolve(account.get("credentialRef", "")) is not None,
                    "modelRateLimits": account.get("modelRateLimits") or {},
                })
            return {"accounts": rows}

        @app.post("/api/management/accounts/{account_id}/enabled")
        async def account_set_enabled(account_id: str, request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return JSONResponse({"error": "invalid JSON body"}, status_code=400)
            self.pool.set_enabled(account_id, bool(body.get("enabled")))
            return {"ok": True}

        @app.post("/api/management/accounts/{account_id}/delete")
        async def account_delete(account_id: str, request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            removed = self.pool.remove(account_id, self.credentials)
            return {"ok": removed}

        @app.get("/api/management/eac")
        async def eac_status(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            return self._eac_status()

        @app.post("/api/management/eac/gateway")
        async def eac_gateway(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return JSONResponse({"error": "invalid JSON body"}, status_code=400)
            if not isinstance(body, dict):
                return JSONResponse({"error": "the request body must be a JSON object"}, status_code=400)
            from .eac import save_gateway_config
            mode = body.get("mode") if body.get("mode") in ("worker", "direct") else "worker"
            base = str(body.get("base") or "").strip().rstrip("/")
            if base == "" or not base.startswith(("http://", "https://")):
                return JSONResponse({"error": "网关地址必须是以 http(s):// 开头的完整地址"}, status_code=400)
            config: dict[str, Any] = {"mode": mode, "base": base}
            if mode == "worker":
                sign_key = str(body.get("signKey") or "").strip()
                if sign_key == "":
                    return JSONResponse({"error": "worker 模式必须填写 HMAC 签名密钥"}, status_code=400)
                config["signKey"] = sign_key
            else:
                api_key = str(body.get("apiKey") or "").strip()
                if api_key == "":
                    return JSONResponse({"error": "direct 模式必须填写网关 API Key"}, status_code=400)
                config["apiKey"] = api_key
            models = body.get("models")
            if isinstance(models, list):
                config["models"] = [str(m).strip() for m in models if isinstance(m, str) and str(m).strip()]
            save_gateway_config(self.data_dir, config)
            # 让新配置立即生效（重新拉一次目录，不触发探测）。
            with contextlib.suppress(Exception):
                await self.runtime["refreshCatalog"](probe=False)
            return {"ok": True, "status": self._eac_status()}

        @app.post("/api/management/eac/gateway/clear")
        async def eac_gateway_clear(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            from .eac import invalidate_cache
            with contextlib.suppress(OSError):
                os.remove(os.path.join(self.data_dir, "eac", "sealed.json"))
            invalidate_cache()
            with contextlib.suppress(Exception):
                await self.runtime["refreshCatalog"](probe=False)
            return {"ok": True, "status": self._eac_status()}

        @app.post("/api/management/eac/login/start")
        async def eac_login_start(request: Request):
            """按原版流程发起 GitHub 授权：向网关登记 link 并打开浏览器。"""
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            from .eac import open_external, start_github_login
            credential = self._sealed_credential()
            if credential is None:
                return JSONResponse({"error": "EAC 车道不可用（密封凭据无法解锁）"}, status_code=503)
            try:
                started = await start_github_login(credential)
            except Exception as error:  # noqa: BLE001
                return JSONResponse({"error": str(error)}, status_code=502)
            started["opened"] = open_external(started["url"])
            return started

        @app.get("/api/management/eac/login/poll")
        async def eac_login_poll(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            from .eac import ack_github_login, poll_github_login, write_user
            credential = self._sealed_credential()
            if credential is None:
                return JSONResponse({"error": "EAC 车道不可用"}, status_code=503)
            link = request.query_params.get("link") or ""
            try:
                result = await poll_github_login(credential, link)
            except Exception as error:  # noqa: BLE001
                return JSONResponse({"error": str(error)}, status_code=400)
            if result.get("status") == "ok" and isinstance(result.get("user"), dict):
                write_user(self.data_dir, result["user"])
                if result.get("ackRequired") is True:
                    await ack_github_login(credential, link, result["user"]["token"])
                return {"status": "ok", "login": result["user"].get("login", ""),
                        "avatar": result["user"].get("avatar", ""), "statusView": self._eac_status()}
            return result

        @app.post("/api/management/eac/github")
        async def eac_github(request: Request):
            """本地 GitHub 授权校验：粘贴令牌 → 核对身份与 star → 本机留档。"""
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return JSONResponse({"error": "invalid JSON body"}, status_code=400)
            from .eac import mint_local_token, verify_github_token, write_user
            try:
                info = await verify_github_token(str((body or {}).get("token") or ""))
            except Exception as error:  # noqa: BLE001
                return JSONResponse({"error": str(error)}, status_code=400)
            write_user(self.data_dir, {
                "token": mint_local_token(), "login": info["login"], "avatar": info["avatar"],
                "name": info["name"], "starred": info["starred"], "repo": info["repo"],
                "verifiedAt": info["checkedAt"], "source": "local-verify",
            })
            note = "" if info["starred"] else f"提示：该账号还没有 star {info['repo']}；上游网关的授权闸门通常要求已 star。"
            return {"ok": True, "user": info, "note": note, "status": self._eac_status()}

        @app.post("/api/management/eac/logout")
        async def eac_logout(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            from .eac import clear_user
            clear_user(self.data_dir)
            return {"ok": True, "status": self._eac_status()}

        @app.get("/api/management/eac/pool")
        async def eac_pool(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            from .eac import fetch_pool, gateway_config
            config = gateway_config(self.data_dir)
            if not config or not config.get("base"):
                return JSONResponse({"error": "尚未配置 EAC 网关"}, status_code=404)
            credential = dict(config)
            from .eac import read_user
            user = read_user(self.data_dir) or {}
            credential["userToken"] = user.get("token")
            try:
                return await fetch_pool(credential)
            except Exception as error:  # noqa: BLE001
                return JSONResponse({"error": str(error)}, status_code=502)

        # ── 请求日志 ────────────────────────────────────────────────────────
        @app.get("/api/management/logs")
        async def logs_list(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            query = request.query_params
            model = (query.get("model") or "").strip() or None
            errors_only = query.get("errors") in ("1", "true", "yes")
            try:
                limit = max(1, min(500, int(query.get("limit") or 100)))
                offset = max(0, int(query.get("offset") or 0))
            except ValueError:
                limit, offset = 100, 0
            return self.logs.list(model=model, errors_only=errors_only, limit=limit, offset=offset)

        @app.get("/api/management/logs/{record_id}")
        async def logs_detail(record_id: int, request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            record = self.logs.get(record_id)
            if record is None:
                return JSONResponse({"error": "日志不存在"}, status_code=404)
            return record

        @app.post("/api/management/logs/clear")
        async def logs_clear(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            self.logs.clear()
            return {"ok": True}

        # ── 在线游乐场 ──────────────────────────────────────────────────────
        @app.post("/api/management/playground/chat")
        async def playground_chat(request: Request):
            deny = self._mgmt_gate(request)
            if deny is not None:
                return deny
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return JSONResponse({"error": "invalid JSON body"}, status_code=400)
            if not isinstance(body, dict):
                return JSONResponse({"error": "the request body must be a JSON object"}, status_code=400)
            model = str(body.get("model") or "").strip()
            if model == "":
                return JSONResponse({"error": "请选择模型"}, status_code=400)
            messages = body.get("messages") if isinstance(body.get("messages"), list) else []
            open_ai: dict[str, Any] = {"model": model, "messages": messages, "stream": True}
            if isinstance(body.get("temperature"), (int, float)):
                open_ai["temperature"] = body["temperature"]
            if isinstance(body.get("max_tokens"), int) and body["max_tokens"] > 0:
                open_ai["max_tokens"] = body["max_tokens"]
            if isinstance(body.get("reasoning_effort"), str) and body["reasoning_effort"] != "":
                open_ai["reasoning_effort"] = body["reasoning_effort"]
            abort_event = asyncio.Event()
            headers = {
                "content-type": "text/event-stream; charset=utf-8",
                "cache-control": "no-store",
                "connection": "keep-alive",
                "x-accel-buffering": "no",
            }
            return StreamingResponse(
                _playground_stream(self.complete, {"model": model, "openAi": open_ai, "abortEvent": abort_event}, abort_event),
                status_code=200, headers=headers)

        # 静态前端
        if FRONTEND_DIR.exists():
            @app.middleware("http")
            async def _no_store_static(request: Request, call_next):
                # 前端是本地工具：禁掉缓存，避免「旧 index.html + 新 app.js」这类
                # 版本错配（曾导致页面交互整块失效）。
                response = await call_next(request)
                if request.url.path == "/" or request.url.path.startswith("/static/"):
                    response.headers["cache-control"] = "no-store"
                return response

            @app.get("/")
            async def index():
                return FileResponse(str(FRONTEND_DIR / "index.html"), headers={"cache-control": "no-store"})

            app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

        return app

    # ── 鉴权与门 ────────────────────────────────────────────────────────────
    async def _v1_gate(self, request: Request) -> Response | None:
        settings = self.stores["settings"].get()
        if settings.get("enabled") is False:
            return openai_error(503, "service_unavailable", "Our Free Model 服务已在设置中暂停")
        forward = settings.get("forward") or {}
        if forward.get("enabled") is False:
            return openai_error(503, "service_unavailable",
                                "本地转发口已在设置中关闭，请在网页控制台开启")
        # Key 校验：auto/custom 都要求匹配 forwardKey；off 则任意（含空）Key 一律放行。
        if (settings.get("forwardKeyMode") or "auto") != "off":
            if not key_matches(_bearer(request), settings.get("forwardKey")):
                return openai_error(401, "invalid_request_error", "missing or invalid API key")
        return None

    def _mgmt_gate(self, request: Request) -> Response | None:
        # 仅回环可访问管理接口（本机单用户工具）。
        if not _is_loopback(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        origin = request.headers.get("origin")
        if origin is not None:
            host = request.headers.get("host", "")
            allowed = {f"http://{host}", f"https://{host}", f"http://127.0.0.1:{self.port}",
                       f"http://localhost:{self.port}"}
            if origin not in allowed:
                return JSONResponse({"error": "forbidden"}, status_code=403)
        return None

    async def _models(self, request: Request) -> Response:
        gate = await self._v1_gate(request)
        if gate is not None:
            return gate
        return json_response(200, {"object": "list", "data": self.runtime["publicModelRows"]()})

    # ── 视图 ────────────────────────────────────────────────────────────────
    def _sealed_credential(self) -> dict | None:
        """当前 EAC 车道凭据（自配网关优先，否则内置密封凭据）+ 用户授权令牌。"""
        from .eac import unlock_sealed_lane
        return unlock_sealed_lane(data_dir=self.data_dir)

    def _eac_status(self) -> dict:
        from .eac import gateway_config, read_user
        config = gateway_config(self.data_dir) or {}
        user = read_user(self.data_dir) or {}
        credential = self._sealed_credential()
        catalog = self.runtime["get_catalog"]() if self.runtime is not None else []
        return {
            # 车道是否可用（内置密封凭据解开、或用户自配网关有效）
            "laneAvailable": credential is not None,
            "builtin": bool((credential or {}).get("builtin")),
            "customGateway": bool(config.get("base")),
            "mode": (credential or {}).get("mode") or "",
            "base": _mask_endpoint((credential or {}).get("base") or ""),
            # 授权
            "authorized": bool(user.get("token")),
            "login": user.get("login") or "",
            "avatar": user.get("avatar") or "",
            "starred": user.get("starred") is True,
            "repo": user.get("repo") or "",
            "verifiedAt": user.get("verifiedAt") or 0,
            "source": user.get("source") or "",
            "modelsInCatalog": sum(1 for e in catalog if e.get("channel") == "eac"),
        }

    def _settings_view(self) -> dict:
        settings = self.stores["settings"].get()
        forward = settings.get("forward") or {}
        egress = settings.get("egress") or {}
        return {
            "enabled": settings.get("enabled") is not False,
            "exposeRegionModels": settings.get("exposeRegionModels") is not False,
            "probeIntervalMinutes": settings.get("probeIntervalMinutes") or 15,
            "defaultMaxTokens": settings.get("defaultMaxTokens") or 32768,
            "streamRecovery": settings.get("streamRecovery") is not False,
            "catalogSyncedAt": settings.get("catalogSyncedAt") or 0,
            "forward": {
                "enabled": forward.get("enabled") is True,
                "host": forward.get("host") or "127.0.0.1",
                "port": self.port,
                "hasKey": bool(settings.get("forwardKey")),
                "keyMode": settings.get("forwardKeyMode") or "auto",
                "lan": {
                    "enabled": (forward.get("lan") or {}).get("enabled") is True,
                    "running": self.relay is not None,
                    "port": (self.relay.bound_port if self.relay is not None else (forward.get("lan") or {}).get("port") or 0),
                    "host": (self.relay.host if self.relay is not None else "0.0.0.0"),
                    "hasKey": bool(settings.get("forwardLanKey")),
                    "addresses": (rank_lan_addresses() if self.relay is not None else []),
                },
            },
            "egress": {
                "enabled": egress.get("enabled") is True,
                "mode": egress.get("mode") or "client",
                "hasUrl": bool(str(egress.get("url") or "")),
                "urlLabel": _mask_url(egress.get("url") or ""),
            },
        }

    def _summary(self) -> dict:
        catalog = self.runtime["get_catalog"]()
        availability = self.stores["availability"].get()
        results = availability.get("results") or {}
        rows = []
        for entry in catalog:
            verdict = results.get(entry["id"]) or {}
            if entry.get("channel"):
                state, detail, probed_at = "available", "", 0
            else:
                state = verdict.get("state", "unknown")
                detail = verdict.get("detail", "")
                probed_at = verdict.get("at", 0)
            rows.append({**entry, "availability": state, "detail": detail, "probedAt": probed_at})
        return {
            "version": __version__,
            "product": PRODUCT,
            "catalog": rows,
            "settings": self._settings_view(),
            "stats": self._stats_totals(),
            "probedAt": availability.get("at", 0),
            "egress": availability.get("egress"),
            "gatewayLatency": self.runtime["get_gateway_latency"](),
            "counts": {
                "total": len(rows),
                "available": sum(1 for r in rows if r["availability"] == "available"),
                "regionBlocked": sum(1 for r in rows if r["availability"] == "region-blocked"),
                "unavailable": sum(1 for r in rows if r["availability"] == "unavailable"),
            },
        }

    def _stats_totals(self) -> dict:
        state = self.stores["stats"].get()
        totals = {"input": 0, "output": 0, "reasoning": 0, "cacheRead": 0, "calls": 0, "failed": 0}
        for row in (state.get("models") or {}).values():
            for key in totals:
                totals[key] += row.get(key, 0)
        logical = state.get("logical") or {}
        return {"totals": totals, "requests": state.get("requests", 0), "failedRequests": state.get("failedRequests", 0),
                "logical": {"turns": logical.get("turns", 0), "failed": logical.get("failed", 0), "recovered": logical.get("recovered", 0)}}

    def _stats(self) -> dict:
        state = self.stores["stats"].get()
        days = sorted((state.get("days") or {}).items())
        return {
            "totals": self._stats_totals(),
            "models": [{"model": model, **row} for model, row in (state.get("models") or {}).items()],
            "days": [{"day": day, "total": bucket.get("total", 0)} for day, bucket in days[-30:]],
            "samples": (state.get("samples") or [])[-40:],
        }

    async def _settings_post(self, request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "the request body must be a JSON object"}, status_code=400)
        current = self.stores["settings"].get()
        patch: dict[str, Any] = {}
        for key in ("enabled", "exposeRegionModels", "streamRecovery"):
            if isinstance(body.get(key), bool):
                patch[key] = body[key]
        for key in ("probeIntervalMinutes", "defaultMaxTokens"):
            if body.get(key) is not None:
                value = _positive_int(body[key])
                if value is None:
                    return JSONResponse({"error": f"{key} must be a positive integer"}, status_code=400)
                patch[key] = value
        if isinstance(body.get("forward"), dict):
            forward = {**(current.get("forward") or {})}
            if isinstance(body["forward"].get("enabled"), bool):
                forward["enabled"] = body["forward"]["enabled"]
            if isinstance(body["forward"].get("lan"), dict):
                lan = {**(forward.get("lan") or {})}
                src_lan = body["forward"]["lan"]
                if isinstance(src_lan.get("enabled"), bool):
                    lan["enabled"] = src_lan["enabled"]
                if src_lan.get("port") is not None:
                    port = _nonneg_int(src_lan["port"])
                    if port is None:
                        return JSONResponse({"error": "lan.port must be an integer between 0 and 65535"}, status_code=400)
                    lan["port"] = port
                forward["lan"] = lan
            patch["forward"] = forward
        if body.get("forwardKeyMode") in ("auto", "custom", "off"):
            patch["forwardKeyMode"] = body["forwardKeyMode"]
        if isinstance(body.get("forwardKey"), str):
            value = body["forwardKey"].strip()
            mode = patch.get("forwardKeyMode") or current.get("forwardKeyMode") or "auto"
            if value:
                patch["forwardKey"] = value[:256]
            elif mode == "custom":
                return JSONResponse({"error": "自定义模式下 API Key 不能为空"}, status_code=400)
        if isinstance(body.get("egress"), dict):
            egress = {**(current.get("egress") or {})}
            src = body["egress"]
            if isinstance(src.get("enabled"), bool):
                egress["enabled"] = src["enabled"]
            if src.get("mode") in ("client", "subscription"):
                egress["mode"] = src["mode"]
            if isinstance(src.get("url"), str):
                egress["url"] = src["url"].strip()[:2048]
            patch["egress"] = egress
        self.stores["settings"].update(patch)
        self.stores["settings"].flush()
        await self._sync_relay()
        return JSONResponse({"ok": True, "settings": self._settings_view()})


_PLAYGROUND_END = object()


def _playground_sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _error_text(error) -> str:
    status = getattr(error, "status_code", None)
    if isinstance(status, int) and 400 <= status <= 599:
        return str(getattr(error, "message", None) or error)
    return str(error)


async def _playground_stream(complete, request: dict, abort_event: asyncio.Event):
    """把一次转发折叠成游乐场用的精简 SSE（delta / reasoning / tool / error / done）。"""
    queue: asyncio.Queue = asyncio.Queue()

    async def pump() -> None:
        try:
            outcome = await complete(request, lambda chunk: queue.put_nowait(chunk))
            queue.put_nowait(("__outcome__", outcome))
        except BaseException as error:  # noqa: BLE001
            queue.put_nowait(("__error__", error))
        finally:
            queue.put_nowait(_PLAYGROUND_END)

    task = asyncio.create_task(pump())
    try:
        outcome = None
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield b": ping\n\n"
                continue
            if item is _PLAYGROUND_END:
                break
            if isinstance(item, tuple):
                if item[0] == "__outcome__":
                    outcome = item[1]
                else:
                    yield _playground_sse({"error": _error_text(item[1])})
                continue
            ctype = item.get("type")
            if ctype == "text-delta":
                yield _playground_sse({"delta": item.get("text") or ""})
            elif ctype == "reasoning-delta":
                yield _playground_sse({"reasoning": item.get("text") or ""})
            elif ctype == "tool-call-delta" and item.get("name"):
                yield _playground_sse({"tool": item.get("name")})
        if outcome is not None and outcome.get("error") is not None:
            yield _playground_sse({"error": str(outcome["error"])})
        yield _playground_sse({"done": True, "usage": (outcome or {}).get("usage"),
                               "truncated": (outcome or {}).get("truncated") is True})
        yield b"data: [DONE]\n\n"
    finally:
        abort_event.set()
        if not task.done():
            task.cancel()
        try:
            await task
        except BaseException:  # noqa: BLE001
            pass


def _positive_int(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _nonneg_int(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _mask_endpoint(url: str) -> str:
    """只展示 scheme://host/path，丢掉 userinfo 与 query（可能含凭据）。"""
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"
    except Exception:  # noqa: BLE001
        return "(set)"


def _mask_url(url: str) -> str:
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname}"
    except Exception:  # noqa: BLE001
        return "(set)"
