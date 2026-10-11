"""渠道凭据存储与账号池。

与原版一致：凭据只写入本机文件（数据目录内，权限收紧），账号池保存每个账号的
启用状态、模型级限流解禁时刻、永久积分锁定与昵称/优先级。选号策略建立在
「模型未受限且账号未被停用」的基础上。
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from typing import Any


def _write_private(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = f"{path}.{os.getpid()}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    os.replace(temp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class CredentialStore:
    """``{ref: value}`` 形式的凭据文件。"""

    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "channel-credentials.json")
        self._lock = threading.Lock()
        self._value: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self._value = {str(k): str(v) for k, v in data.items()}
        except (FileNotFoundError, ValueError, OSError):
            self._value = {}

    def resolve(self, ref: str) -> str | None:
        return self._value.get(ref)

    def set(self, ref: str, value: str) -> None:
        with self._lock:
            self._value[ref] = value
            _write_private(self.path, self._value)

    def delete(self, ref: str) -> bool:
        with self._lock:
            if ref not in self._value:
                return False
            del self._value[ref]
            _write_private(self.path, self._value)
            return True

    def refs(self) -> list[str]:
        return list(self._value.keys())


class AccountPool:
    """账号条目与选号。

    条目字段（对齐原版语义）：``id`` / ``provider`` / ``enabled`` / ``credentialRef`` /
    ``nickname`` / ``priority`` / ``modelRateLimits`` / ``refreshable``。
    """

    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "channel-pack", "accounts.json")
        self._lock = threading.Lock()
        self._accounts: list[dict] = []
        self._permanent_locked: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self._accounts = data.get("accounts") if isinstance(data.get("accounts"), list) else []
                locked = data.get("permanentLocked") if isinstance(data.get("permanentLocked"), list) else []
                self._permanent_locked = set(str(x) for x in locked)
        except (FileNotFoundError, ValueError, OSError):
            self._accounts = []

    def _flush(self) -> None:
        _write_private(self.path, {"accounts": self._accounts, "permanentLocked": sorted(self._permanent_locked)})

    def list_all(self) -> list[dict]:
        return list(self._accounts)

    def list_by_provider(self, provider: str) -> list[dict]:
        return [a for a in self._accounts if a.get("provider") == provider]

    def add(self, *, provider: str, credential_ref: str, nickname: str = "", credential_value: str | None = None,
            creds: CredentialStore | None = None) -> str:
        account_id = f"{provider}-{secrets.token_hex(4)}"
        entry = {
            "id": account_id, "provider": provider, "credentialRef": credential_ref,
            "nickname": nickname or account_id, "enabled": True, "priority": self.list_by_provider(provider).__len__(),
            "modelRateLimits": {}, "refreshable": True, "createdAt": int(time.time() * 1000),
        }
        with self._lock:
            self._accounts.append(entry)
            self._flush()
        if credential_value is not None and creds is not None:
            creds.set(credential_ref, credential_value)
        return account_id

    def update_model_rate_limit(self, account_id: str, model_id: str, reset_at_ms: int) -> None:
        with self._lock:
            for account in self._accounts:
                if account.get("id") == account_id:
                    limits = dict(account.get("modelRateLimits") or {})
                    limits[model_id] = reset_at_ms
                    account["modelRateLimits"] = limits
            self._flush()

    def set_enabled(self, account_id: str, enabled: bool) -> None:
        with self._lock:
            for account in self._accounts:
                if account.get("id") == account_id:
                    account["enabled"] = bool(enabled)
            self._flush()

    def get(self, account_id: str) -> dict | None:
        return next((a for a in self._accounts if a.get("id") == account_id), None)

    def remove(self, account_id: str, credentials: "CredentialStore | None" = None) -> bool:
        """删除账号条目；给了凭据存储则同时清除其凭据。"""
        with self._lock:
            target = next((a for a in self._accounts if a.get("id") == account_id), None)
            if target is None:
                return False
            self._accounts = [a for a in self._accounts if a.get("id") != account_id]
            self._flush()
        if credentials is not None and isinstance(target.get("credentialRef"), str):
            credentials.delete(target["credentialRef"])
        return True

    def permanent_locked(self, provider: str) -> bool:
        return provider in self._permanent_locked

    def set_permanent_locked(self, provider: str, locked: bool) -> None:
        with self._lock:
            if locked:
                self._permanent_locked.add(provider)
            else:
                self._permanent_locked.discard(provider)
            self._flush()

    def get_available_account(self, provider: str, model_id: str = "", exclude: set[str] | None = None) -> dict | None:
        """按「启用 + 模型未限流」筛选，返回第一个可用账号。"""
        exclude = exclude or set()
        now = int(time.time() * 1000)
        candidates = [a for a in self.list_by_provider(provider) if a.get("enabled") and a.get("id") not in exclude]
        candidates.sort(key=lambda a: a.get("priority", 0))
        for account in candidates:
            if model_id:
                reset_at = (account.get("modelRateLimits") or {}).get(model_id, 0)
                if reset_at and now < reset_at:
                    continue
            return account
        return None
