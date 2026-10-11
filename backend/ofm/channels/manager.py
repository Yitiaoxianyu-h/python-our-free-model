"""渠道管理器：把各账号渠道的凭据、账号池、模型目录与推理接入到主链路。

**模块约定**（每个已接入渠道一个自包含模块 ``ofm/channels/<channel_id>.py``）：

    CHANNEL_ID: str
    async def run_login() -> dict                     # 完成一次登录，返回凭据 dict
    async def refresh_credential(credential) -> dict  # 可选；无则视为不可续期
    async def fetch_models(credential) -> dict        # {"models":[{"id","name"}], ...}
    async def stream(body, credential, *, catalog=None, on_refresh=None) -> AsyncIterator[chunk]

``stream`` 产出的 chunk 为内部块协议（text-delta / reasoning-delta / tool-call-delta /
usage / finish），可直接被转发层折叠。管理器负责目录并入主目录、按
``<channel>/<model>`` 分派推理、以及登录生命周期。
"""

from __future__ import annotations

import asyncio
import importlib
import json
import secrets
import time
from typing import Any, AsyncIterator

from ..http_client import CODE, UpstreamError
from .registry import CHANNELS

# 免密车道不是账号渠道，不参与本管理器。
NON_ACCOUNT = {"anonymous", "kilo"}


def _module_name(channel_id: str) -> str:
    return f"{__package__}.{channel_id}"


class ChannelManager:
    def __init__(self, *, data_dir: str, credentials, pool, logger=print):
        self.data_dir = data_dir
        self.credentials = credentials
        self.pool = pool
        self.log = logger
        self._catalog: dict[str, dict] = {}
        self._logins: dict[str, asyncio.Task] = {}
        self._login_result: dict[str, dict] = {}
        self._modules: dict[str, Any] = {}

    # ── 模块 ────────────────────────────────────────────────────────────────
    def implemented(self) -> list[str]:
        return [c["id"] for c in CHANNELS if c["implemented"] and c["id"] not in NON_ACCOUNT]

    def _module(self, channel_id: str):
        if channel_id in self._modules:
            return self._modules[channel_id]
        try:
            module = importlib.import_module(_module_name(channel_id))
        except Exception as error:  # noqa: BLE001
            self.log(f"[channels] {channel_id} 模块加载失败：{error}")
            module = None
        self._modules[channel_id] = module
        return module

    # ── 目录 ────────────────────────────────────────────────────────────────
    async def refresh_catalog(self) -> None:
        for channel_id in self.implemented():
            module = self._module(channel_id)
            if module is None or not hasattr(module, "fetch_models"):
                continue
            account = self.pool.get_available_account(channel_id, "")
            if account is None:
                continue
            credential = self._load_credential(account)
            if credential is None:
                continue
            try:
                data = await module.fetch_models(credential)
                self._catalog[channel_id] = {**data, "at": int(time.time() * 1000)}
            except Exception as error:  # noqa: BLE001
                self.log(f"[channels] {channel_id} 目录刷新失败：{error}")

    def catalog_entries(self) -> list[dict]:
        """产出可并入主目录的条目（``id`` 形如 ``<channel>/<model>``）。"""
        out: list[dict] = []
        for channel_id in self.implemented():
            data = self._catalog.get(channel_id)
            if not data:
                continue
            module = self._module(channel_id)
            tag = next((c["name"] for c in CHANNELS if c["id"] == channel_id), channel_id)
            for model in data.get("models", []):
                upstream_id = str(model.get("id") or "")
                if upstream_id == "":
                    continue
                context = model.get("contextWindow") or _context_for(module, upstream_id)
                entry = {
                    "id": f"{channel_id}/{upstream_id}",
                    "upstreamId": upstream_id,
                    "name": f"{tag} {model.get('name') or upstream_id}",
                    "channel": channel_id,
                    "wire": "chat",
                    "vision": bool(model.get("vision")),
                    "reasoning": bool(model.get("reasoning")),
                    "contextWindow": context,
                    "maxOutput": model.get("maxOutput") or 32768,
                    "canDisableThinking": bool(model.get("canDisableThinking")),
                    "regionSensitive": False,
                }
                # 渠道自己声明的思考档位（若有）一并透出，供选择器展示。
                if isinstance(model.get("efforts"), list) and model["efforts"]:
                    entry["efforts"] = [str(level) for level in model["efforts"]]
                    entry["effortDefault"] = model.get("effortDefault") or entry["efforts"][0]
                out.append(entry)
        return out

    # ── 凭据 ────────────────────────────────────────────────────────────────
    def _load_credential(self, account: dict) -> dict | None:
        raw = self.credentials.resolve(account.get("credentialRef", ""))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def _store_credential(self, credential_ref: str, credential: dict) -> None:
        self.credentials.set(credential_ref, json.dumps(credential, ensure_ascii=False))

    def account_count(self, channel_id: str) -> int:
        return len(self.pool.list_by_provider(channel_id))

    # ── 推理分派 ────────────────────────────────────────────────────────────
    async def stream(self, entry: dict, open_ai: dict) -> AsyncIterator[dict]:
        channel_id = entry.get("channel")
        model_id = entry.get("upstreamId")
        account = self.pool.get_available_account(channel_id, model_id or "")
        if account is None:
            raise UpstreamError(f"{channel_id}: 没有可用账号，请先在网页控制台登录", CODE["credential"])
        credential = self._load_credential(account)
        if credential is None:
            raise UpstreamError(f"{channel_id}: 账号凭据不可用，请重新登录", CODE["credential"])
        module = self._module(channel_id)
        if module is None or not hasattr(module, "stream"):
            raise UpstreamError(f"{channel_id}: 该渠道的推理尚未移植", CODE["server"])

        def on_refresh(fresh: dict) -> None:
            self._store_credential(account["credentialRef"], fresh)

        body = {**open_ai, "model": model_id}
        async for chunk in module.stream(body, credential, catalog=self._catalog.get(channel_id) or {},
                                         on_refresh=on_refresh):
            yield chunk

    # ── 登录 ────────────────────────────────────────────────────────────────
    async def start_login(self, channel_id: str) -> dict:
        if channel_id not in self.implemented():
            return {"error": "channel-not-implemented", "channel": channel_id}
        module = self._module(channel_id)
        if module is None or not (hasattr(module, "run_login") or hasattr(module, "start_login")):
            return {"error": "login-not-implemented", "channel": channel_id}
        task = self._logins.get(channel_id)
        if task is not None and not task.done():
            return {"status": "pending", "note": "登录流程已在进行中"}

        # 分步登录（短信 / 扫码）：模块自带 start_login / submit_login_code。
        if hasattr(module, "start_login") and not hasattr(module, "run_login"):
            self._login_result[channel_id] = {"status": "pending"}
            try:
                started = await module.start_login()
            except Exception as error:  # noqa: BLE001
                self._login_result[channel_id] = {"status": "error", "message": str(error)}
                return {"error": str(error)}
            self._login_result[channel_id] = {"status": "awaiting-code", **started}
            return self._login_result[channel_id]

        self._login_result[channel_id] = {"status": "pending"}

        async def run():
            try:
                credential = await module.run_login()
                await self._register(channel_id, credential)
            except Exception as error:  # noqa: BLE001
                self._login_result[channel_id] = {"status": "error", "message": str(error)}

        self._logins[channel_id] = asyncio.create_task(run())
        return {"status": "pending", "note": "已发起登录，完成后会自动保存账号"}

    async def submit_login(self, channel_id: str, payload: dict) -> dict:
        """分步登录的下一步：提交手机号/验证码（或轮询扫码结果）。

        模块可返回：
        - 含 ``access_token`` 的凭据 dict → 注册账号，返回 ``{status: ok}``；
        - 含 ``status`` 的 dict（如 ``awaiting-code``）→ 作为下一步状态返回，前端继续渲染；
        - ``None`` → 保持当前状态。
        """
        module = self._module(channel_id)
        if module is None or not hasattr(module, "submit_login"):
            return {"error": "login-not-implemented", "channel": channel_id}
        try:
            result = await module.submit_login(payload)
        except Exception as error:  # noqa: BLE001
            self._login_result[channel_id] = {"status": "error", "message": str(error)}
            return {"error": str(error)}
        if isinstance(result, dict):
            if result.get("access_token"):
                await self._register(channel_id, result)
                return {"status": "ok"}
            if "status" in result:
                self._login_result[channel_id] = result
                return result
        return self._login_result.get(channel_id, {"status": "awaiting-code"})

    async def _register(self, channel_id: str, credential: dict) -> None:
        ref = self._next_ref(channel_id)
        self._store_credential(ref, credential)
        nickname = (credential.get("nickname") or credential.get("user_name") or credential.get("email")
                    or credential.get("phone") or channel_id)
        self.pool.add(provider=channel_id, credential_ref=ref, nickname=nickname)
        self._login_result[channel_id] = {"status": "ok", "account": ref}
        await self.refresh_catalog()


    def login_result(self, channel_id: str) -> dict:
        return self._login_result.get(channel_id, {"status": "idle"})

    def _next_ref(self, channel_id: str) -> str:
        return f"{channel_id.upper()}_ACCOUNT_{secrets.token_hex(4).upper()}"


def _context_for(module, model_id: str) -> int:
    windows = getattr(module, "CONTEXT_WINDOWS", None)
    if isinstance(windows, dict) and isinstance(windows.get(model_id), int):
        return windows[model_id]
    return 131072
