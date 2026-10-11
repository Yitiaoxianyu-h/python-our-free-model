"""EAC 协付渠道：密封凭据、签名请求、GitHub 授权闸门。

原版语义（本文件逐条对齐）：

- 车道有两种模式：
  - ``worker``（推荐）：凭据里只有**签名网关地址**与**共享 HMAC 签名密钥**，
    每次请求带 ``x-ofm-timestamp`` 与 ``x-ofm-signature``：
    ``HMAC-SHA256(signKey, f"{ts}\\n{METHOD}\\n{path}\\n{sha256hex(body)}")``；
  - ``direct``：直接用 ``Authorization: Bearer <apiKey>`` 打网关。
- 网关的 **GitHub 授权闸门**要求对话请求额外带 ``x-ofm-user``（专属令牌），
  该令牌只发给「用 GitHub 登录 + 已 star 本仓库」的账号。
- 凭据缺失/未授权时，该渠道**整体不出现**，且不会发起任何请求。

本移植版把「解锁」拆成两步，让用户能自己走完：
1. **配置网关**（``data/eac/sealed.json``）——你有自己的 EAC 兼容网关时填这里；
2. **GitHub 授权**（``data/eac/user.json``）——两种方式：
   - 有网关：走网关的 ``/auth/github/start`` + 轮询（与原版一致，令牌由网关签发）；
   - 没有网关：用**本地校验**（粘贴 GitHub 令牌，本机调 GitHub API 核对 star 状态），
     校验通过后在本机留档。注意：本地校验只能证明「你授权了」，真正对话仍需可用网关。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx

from .http_client import (
    CODE,
    UpstreamError,
    _read_remainder,
    _replay,
    get_client,
    read_head,
    read_sse,
    sniff_body,
)

CHANNEL_ID = "eac"

GITHUB_API = "https://api.github.com"
#: GitHub 授权校验的目标仓库（与原版一致）。
GITHUB_REPO = "Ebony-Vinyl/dsh-our-free-model"

LISTING_TIMEOUT_S = 15
TURN_TIMEOUT_S = 300
POOL_TIMEOUT_S = 20
AUTH_TIMEOUT_S = 15

_SEALED_CACHE: dict[str, Any] = {"path": None, "data": None, "loaded": False}


# ── 配置与授权落盘 ──────────────────────────────────────────────────────────

def _sealed_path(data_dir: str) -> str:
    return os.path.join(data_dir, "eac", "sealed.json")


def _user_path(data_dir: str) -> str:
    return os.path.join(data_dir, "eac", "user.json")


def _read_json(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_json(path: str, value: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = f"{path}.{os.getpid()}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
    os.replace(temp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def unlock_sealed_lane(*, data_dir: str | None = None, profile_name: str | None = None) -> dict | None:
    """解锁车道：优先用户自配网关，否则用**仓库内置的密封凭据**（与上游一致）。

    内置凭据以 AES-256-GCM 密文形式随包分发（``ofm/eac_vault_data.py``），
    解锁时才派生密钥解密（``ofm/eac_vault.py``），明文不落盘、不落日志。
    """
    if data_dir is None:
        return None
    # 1) 用户自配网关（``data/eac/sealed.json``）优先
    path = _sealed_path(data_dir)
    if _SEALED_CACHE["loaded"] and _SEALED_CACHE["path"] == path:
        data = _SEALED_CACHE["data"]
    else:
        data = _read_json(path)
        if not isinstance(data, dict) or not isinstance(data.get("base"), str) or data["base"] == "":
            data = None
        _SEALED_CACHE.update({"path": path, "loaded": True, "data": data})
    # 2) 没有自配网关就用内置密封凭据
    if data is None:
        try:
            from .eac_vault import unlock_sealed_lane as unlock_builtin
            opened = unlock_builtin()
        except Exception:  # noqa: BLE001
            opened = None
        if opened is None:
            return None
        data = {
            "mode": opened["mode"], "base": opened["base"], "flavor": opened.get("flavor", ""), "builtin": True,
            **({"signKey": opened["signingSecret"]} if opened.get("signingSecret") else {}),
            **({"apiKey": opened["apiKey"]} if opened.get("apiKey") else {}),
        }
    credential = dict(data)
    user = read_user(data_dir)
    credential["userToken"] = user.get("token") if isinstance(user, dict) else None
    return credential


def read_user(data_dir: str) -> dict | None:
    return _read_json(_user_path(data_dir))


def write_user(data_dir: str, user: dict) -> None:
    _write_json(_user_path(data_dir), user)


def clear_user(data_dir: str) -> None:
    try:
        os.remove(_user_path(data_dir))
    except OSError:
        pass


def save_gateway_config(data_dir: str, config: dict) -> None:
    _write_json(_sealed_path(data_dir), config)
    invalidate_cache()


def invalidate_cache() -> None:
    """让下一次 ``unlock_sealed_lane`` 重新读盘（配置增删改后调用）。"""
    _SEALED_CACHE.update({"loaded": False, "data": None, "path": None})


def gateway_config(data_dir: str) -> dict | None:
    return _read_json(_sealed_path(data_dir))


# ── 签名 ────────────────────────────────────────────────────────────────────

def sign_sealed_request(signing_secret: str, method: str, path: str, body: str = "",
                        now_ms: int | None = None) -> dict[str, str]:
    """原版 ``signSealedRequest`` 的逐字复刻（path 用完整 URL 的 pathname）。"""
    timestamp = str(int(now_ms if now_ms is not None else time.time() * 1000))
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    payload = f"{timestamp}\n{method.upper()}\n{path}\n{body_hash}"
    mac = hmac.new(signing_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"x-ofm-timestamp": timestamp, "x-ofm-signature": mac}


def _headers(credential: dict, method: str, url: str, body: str) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "accept": "text/event-stream" if method.upper() == "POST" else "application/json",
        "user-agent": "our-free-model",
    }
    if credential.get("mode") == "worker":
        path = urlsplit(url).path
        headers.update(sign_sealed_request(str(credential.get("signKey") or ""), method, path, body))
        token = credential.get("userToken")
        if isinstance(token, str) and token:
            headers["x-ofm-user"] = token
        return headers
    headers["authorization"] = f"Bearer {credential.get('apiKey', '')}"
    return headers


def _describe(error: BaseException) -> str:
    """异常文案兜底：httpx 某些传输错误 str() 为空，至少要给出类型名。"""
    text = str(error).strip()
    if text:
        return text
    cause = getattr(error, "__cause__", None)
    if cause is not None and str(cause).strip():
        return f"{type(error).__name__}: {cause}"
    return type(error).__name__


def _base_of(credential: dict) -> str:
    base = str(credential.get("base") or "").rstrip("/")
    if base == "":
        raise UpstreamError("the EAC lane has no gateway address", CODE["authorization"])
    return base


# ── 车道请求 ────────────────────────────────────────────────────────────────

async def fetch_sealed_listing(credential: dict, timeout_ms: int = LISTING_TIMEOUT_S * 1000) -> dict:
    """``GET {base}/models``；拉不到时退回配置里声明的名单（不抛错）。"""
    declared = credential.get("models")
    fallback = {"data": [{"id": m} for m in declared if isinstance(m, str)]} if isinstance(declared, list) and declared else None
    if credential.get("mode") != "worker" and fallback is not None:
        # 非签名网关且已声明名单：直接用本地名单，不发请求。
        return fallback
    url = f"{_base_of(credential)}/models"
    client = await get_client()
    try:
        response = await client.get(url, headers=_headers(credential, "GET", url, ""), timeout=timeout_ms / 1000)
        if response.status_code >= 400:
            raise _classify(response.status_code, response.text)
        return response.json()
    except (httpx.HTTPError, UpstreamError) as error:
        if fallback is not None:
            return fallback
        if isinstance(error, httpx.HTTPError):
            raise UpstreamError(f"eac: model listing failed: {_describe(error)}", CODE["transport"])
        raise


async def fetch_pool(credential: dict, timeout_ms: int = POOL_TIMEOUT_S * 1000) -> dict:
    """资源池读数（``GET {base}/pool``）。"""
    url = f"{_base_of(credential)}/pool"
    client = await get_client()
    try:
        response = await client.get(url, headers=_headers(credential, "GET", url, ""), timeout=timeout_ms / 1000)
    except httpx.HTTPError as error:
        raise UpstreamError(f"eac: pool unavailable: {error}", CODE["transport"])
    if response.status_code >= 400:
        raise _classify(response.status_code, response.text)
    return response.json()


async def post_sealed_streamed(credential: dict, body: dict, on_data: Callable[[str], None],
                               timeout_ms: int = TURN_TIMEOUT_S * 1000) -> None:
    """``POST {base}/chat/completions``：签名 + SSE（形状嗅探，与免费车道同一套纪律）。"""
    base = _base_of(credential)
    url = f"{base}/chat/completions"
    # 签名覆盖 sha256(body)，所以发出的字节必须与签名时**逐字一致**。
    body_text = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    client = await get_client()
    timeout_s = max(1.0, timeout_ms / 1000)
    try:
        async with client.stream("POST", url, headers=_headers(credential, "POST", url, body_text),
                                 content=body_text,
                                 timeout=httpx.Timeout(connect=15.0, read=timeout_s, write=60.0, pool=15.0)) as response:
            if response.status_code >= 400:
                text = (await response.aread()).decode("utf-8", "replace")
                raise _classify(response.status_code, text)
            head = await read_head(response.aiter_bytes(), 4096, timeout_s)
            shape = sniff_body(head.text)
            if shape == "empty":
                raise UpstreamError("eac: model stream returned no body", CODE["empty"])
            if shape == "sse":
                await read_sse(_replay(head), on_data, timeout_s)
                return
            text = (await _read_remainder(head)).decode("utf-8", "replace")
            try:
                payload = json.loads(text)
            except ValueError:
                raise UpstreamError(f"eac: unexpected non-stream response: {text[:200]}", CODE["server"])
            if isinstance(payload, dict) and payload.get("error"):
                raise _classify(response.status_code, text)
            on_data(json.dumps(payload))
    except UpstreamError:
        raise
    except httpx.HTTPError as error:
        raise UpstreamError(f"eac: model request failed: {error}", CODE["transport"])


def _classify(status: int, text: str) -> UpstreamError:
    raw = text[:300]
    import re
    if re.match(r"^\s*<(!doctype|html)", raw, re.IGNORECASE):
        return UpstreamError(f"eac: the gateway's front proxy answered HTTP {status} with an HTML error page",
                             CODE["server"], status=status)
    if status == 401:
        return UpstreamError("eac: 需要 GitHub 授权（网关返回 401）；请在 EAC 页面完成授权", CODE["authorization"],
                             status=status)
    if status == 403 and re.search(r"signature", raw, re.IGNORECASE):
        return UpstreamError("eac: 网关拒绝了请求签名（body 可能在传输中被改写；请关闭会改写请求体的本地代理插件）",
                             CODE["transport"], status=status)
    if status == 429:
        return UpstreamError(f"eac: 额度/速率受限（429）{raw}", CODE["quota"], status=status)
    if 400 <= status < 500:
        return UpstreamError(f"eac: HTTP {status} {raw}", CODE["client"], status=status)
    return UpstreamError(f"eac: HTTP {status} {raw}", CODE["server"], status=status)


# ── GitHub 授权 ─────────────────────────────────────────────────────────────

async def verify_github_token(token: str) -> dict:
    """用 GitHub 令牌核对身份与 star 状态（本机直连 GitHub API，不经过任何中转）。"""
    if not isinstance(token, str) or token.strip() == "":
        raise UpstreamError("请先填入 GitHub 令牌", CODE["client"])
    token = token.strip()
    headers = {
        "authorization": f"Bearer {token}",
        "accept": "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "our-free-model",
    }
    client = await get_client()
    try:
        me = await client.get(f"{GITHUB_API}/user", headers=headers, timeout=AUTH_TIMEOUT_S)
    except httpx.HTTPError as error:
        raise UpstreamError(f"连接 GitHub 失败：{error}", CODE["transport"])
    if me.status_code == 401:
        raise UpstreamError("GitHub 令牌无效或已过期", CODE["credential"], status=401)
    if me.status_code >= 400:
        raise UpstreamError(f"GitHub 返回 HTTP {me.status_code}", CODE["server"], status=me.status_code)
    profile = me.json()
    login = profile.get("login", "")
    try:
        star = await client.get(f"{GITHUB_API}/user/starred/{GITHUB_REPO}", headers=headers, timeout=AUTH_TIMEOUT_S)
        starred = star.status_code == 204
    except httpx.HTTPError:
        starred = False
    return {
        "login": login,
        "avatar": profile.get("avatar_url", ""),
        "name": profile.get("name") or login,
        "starred": starred,
        "repo": GITHUB_REPO,
        "checkedAt": int(time.time() * 1000),
    }


def mint_local_token() -> str:
    """本地授权令牌（无网关时在机内使用；有网关时用网关签发的令牌）。"""
    return f"ofm-local-{secrets.token_urlsafe(24)}"


# ── 网关侧的 GitHub 授权（与原版 src/eac-login.js 逐条对齐）──────────────────

_LINK_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{16,64}$")


def _root_of(credential: dict) -> str:
    base = _base_of(credential)
    return base[:-3] if base.endswith("/v1") else base


def new_link() -> str:
    return secrets.token_urlsafe(32)


def open_external(url: str) -> bool:
    """用系统浏览器打开授权页（本机工具的一次性动作）。"""
    try:
        import subprocess
        import sys
        if sys.platform == "win32":
            subprocess.Popen(["cmd", "/c", "start", "", url], shell=False)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["xdg-open", url])
        return True
    except Exception:  # noqa: BLE001
        return False


async def start_github_login(credential: dict) -> dict:
    """``GET {root}/auth/github/start?link=``（期望 302，随后由系统浏览器打开）。"""
    link = new_link()
    root = _root_of(credential)
    url = f"{root}/auth/github/start?link={quote(link)}"
    client = await get_client()
    try:
        response = await client.get(url, headers={"accept": "application/json"},
                                    timeout=AUTH_TIMEOUT_S, follow_redirects=False)
    except httpx.HTTPError as error:
        raise UpstreamError(f"eac: 无法连接授权网关（{_describe(error)}）", CODE["transport"])
    if response.status_code != 302:
        raise UpstreamError(f"eac: 授权网关返回 HTTP {response.status_code}（期望 302）", CODE["server"],
                            status=response.status_code)
    return {"link": link, "url": url}


async def poll_github_login(credential: dict, link: str) -> dict:
    """``GET {root}/auth/poll?link=&retain=1``：pending / unstarred / expired / ok。"""
    if not isinstance(link, str) or not _LINK_RE.match(link):
        raise UpstreamError("eac: 授权链接无效", CODE["client"])
    root = _root_of(credential)
    url = f"{root}/auth/poll?link={quote(link)}&retain=1"
    client = await get_client()
    try:
        response = await client.get(url, headers={"accept": "application/json"}, timeout=AUTH_TIMEOUT_S)
    except httpx.HTTPError:
        return {"status": "pending", "error": "unreachable"}
    if response.status_code >= 400:
        return {"status": "pending", "error": f"gateway-http-{response.status_code}"}
    try:
        data = response.json()
    except ValueError:
        return {"status": "pending", "error": "malformed"}
    status = data.get("status")
    if status in ("expired", "pending", "unstarred"):
        return {"status": status, "login": data.get("login") or "", "repo": data.get("repo") or "", "link": link}
    token = data.get("token")
    if status != "ok" or not isinstance(token, str) or token == "":
        return {"status": "pending", "error": "malformed"}
    return {
        "status": "ok", "link": link,
        "ackRequired": data.get("ackRequired") is True,
        "user": {
            "token": token, "login": data.get("login") or "", "avatar": data.get("avatar") or "",
            "repo": data.get("repo") or "", "starred": True,
            "verifiedAt": int(time.time() * 1000), "source": "gateway",
        },
    }


async def ack_github_login(credential: dict, link: str, token: str) -> None:
    """新版网关要求回执（``retain=1`` 的配对动作）；失败不影响已经落盘的凭据。"""
    root = _root_of(credential)
    url = f"{root}/auth/ack?link={quote(link)}"
    client = await get_client()
    try:
        await client.post(url, headers={"accept": "application/json", "x-ofm-user": token}, timeout=5)
    except httpx.HTTPError:
        pass


async def auth_status(credential: dict) -> dict:
    url = f"{_base_of(credential)}/auth/status"
    client = await get_client()
    token = credential.get("userToken")
    headers = _headers(credential, "GET", url, "")
    if isinstance(token, str) and token:
        headers["x-ofm-user"] = token
    try:
        response = await client.get(url, headers=headers, timeout=AUTH_TIMEOUT_S)
    except httpx.HTTPError as error:
        return {"available": True, "authorized": bool(token), "unverified": True, "error": str(error)}
    if response.status_code >= 400:
        return {"available": True, "authorized": bool(token), "unverified": True, "error": f"HTTP {response.status_code}"}
    data = response.json()
    data["available"] = True
    return data
