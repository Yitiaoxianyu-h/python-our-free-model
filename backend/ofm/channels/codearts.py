"""CodeArts（华为云 CodeArts Agent）渠道。

移植自原版 `service.ts` / `login.ts` / `oauth.ts` / `models.ts` / `llm-adapter.ts`：

- 登录：新式 IAM OAuth（浏览器授权 + 本地回调 + PKCE + DPoP），回退旧 ticket 流程；
- 推理：``POST https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions``，
  用 SDK-HMAC-SHA256 签名，SSE 为 OpenAI 兼容格式；
- 模型目录：两个签名 GET 端点合并去重，过滤视觉模型，benefit 集合决定是否带 ``maas_type`` 头；
- 本渠道不支持图片输入（与原版一致）。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any, AsyncIterator, Callable

import httpx

from ..channel import create_channel
from ..http_client import CODE, UpstreamError, get_client, read_head, read_sse, _read_remainder, _replay, sniff_body
from ..stream import read_stream
from .huawei_sign import sign_request

CHAT_API_BASE = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2"
STS_TOKEN_ENDPOINT = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"
PORTAL_AUTHORIZE_BASE = "https://codearts.huaweicloud.com/portal/authorize"
PORTAL_LOGIN_BASE = "https://codearts.huaweicloud.com/portal/login"
CREDENTIAL_ENDPOINT = "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/login/ticket"
OPENGW_GATEWAY_CONFIG_URL = "https://opengw.developer.huaweicloud.com/api/v1/gateway/config"
SNAP_MODEL_BUILTIN_URL = "https://snap-access.cn-north-4.myhuaweicloud.com/v1/model/builtin"

CLIENT_ID = "codearts-agent"
PLUGIN_NAME = "snap_AIIDE"
PLUGIN_VERSION = "5.2.0"
REDIRECT_PATH = "/oauth/callback"

BENEFIT_FALLBACK = ["glm-5.3-flash", "deepseek-v4.1-flash"]

DEFAULT_MODELS = [
    "GLM-5.2", "GLM-5.1", "GLM-5", "glm-5.3-flash",
    "openpangu-2.0-flash", "openpangu-2.0-pro",
    "deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4.1-flash",
]
CONTEXT_WINDOWS = {
    "GLM-5.2": 202752, "glm-5.3-flash": 1048576,
    "deepseek-v4-flash": 1048576, "deepseek-v4-pro": 1048576, "deepseek-v4.1-flash": 1000000,
}

MAX_TOKENS_DEFAULT = 65536
TOKEN_TIMEOUT_S = 60
MODELS_TIMEOUT_S = 10
LOGIN_TIMEOUT_S = 180


# ── PKCE / DPoP ─────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def generate_dpop_keypair() -> tuple[Any, dict, dict]:
    """生成 ES256 P-256 密钥对，返回 (私钥对象, 公钥 JWK, 私钥 JWK)。"""
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.private_numbers()
    public_numbers = numbers.public_numbers

    def _int_bytes(value: int, size: int = 32) -> str:
        return _b64url(value.to_bytes(size, "big"))

    public_jwk = {"kty": "EC", "crv": "P-256",
                  "x": _int_bytes(public_numbers.x), "y": _int_bytes(public_numbers.y)}
    private_jwk = {**public_jwk, "d": _int_bytes(numbers.private_value), "alg": "ES256", "use": "sig"}
    return private_key, public_jwk, private_jwk


def _private_key_from_jwk(jwk: dict) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec

    def _int(value: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")

    return ec.derive_private_key(_int(jwk["d"]), ec.SECP256R1())


def sign_dpop_jws(private_key: Any, public_jwk: dict, htm: str, htu: str) -> str:
    """构造 DPoP 证明：``<header>.<payload>.<signature>``（ES256，签名转 raw R||S）。"""
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes

    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": public_jwk}
    payload = {"htm": htm, "htu": htu, "iat": int(time.time()), "jti": secrets.token_hex(32)}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{_b64url(raw)}"


# ── 登录 ────────────────────────────────────────────────────────────────────

def build_oauth_login_url(port: int, challenge: str, ticket_id: str) -> str:
    from urllib.parse import urlencode

    query = urlencode({
        "theme": "2", "locale": "zh-cn", "uri_scheme": "codearts-agent",
        "client_id": CLIENT_ID, "port": str(port),
        "code_challenge": challenge, "code_challenge_method": "SHA-256",
        "ticket_id": ticket_id, "plugin-name": PLUGIN_NAME, "plugin-version": PLUGIN_VERSION,
    })
    return f"{PORTAL_AUTHORIZE_BASE}?{query}"


def build_portal_login_result_url(succeeded: bool) -> str:
    return f"{PORTAL_LOGIN_BASE}?login_succeed={'true' if succeeded else 'false'}&uri_scheme=codearts-agent&locale=zh-cn"


async def _exchange_token(**form: str) -> dict:
    client = await get_client()
    response = await client.post(STS_TOKEN_ENDPOINT, data=form,
                                 headers={"content-type": "application/x-www-form-urlencoded"},
                                 timeout=TOKEN_TIMEOUT_S)
    payload = response.json()
    if response.status_code >= 400 or payload.get("error"):
        raise UpstreamError(f"codearts token exchange failed: {payload.get('error_msg') or payload.get('error') or response.status_code}",
                            CODE["credential"], status=response.status_code)
    return payload


def credential_from_token_response(payload: dict, *, code_verifier: str | None, private_jwk: dict | None) -> dict:
    credentials = payload.get("credentials") or {}
    credential = {
        "access_key_id": credentials.get("access_key_id", ""),
        "secret_access_key": credentials.get("secret_access_key", ""),
        "security_token": credentials.get("security_token", ""),
        "expires_at": credentials.get("expiration", ""),
    }
    if payload.get("refresh_token"):
        credential["refresh_token"] = payload["refresh_token"]
    if code_verifier:
        credential["code_verifier"] = code_verifier
    if private_jwk:
        credential["dpop_private_key_jwk"] = private_jwk
    return credential


async def poll_ticket(ticket_id: str, secret: str, *, plugin_name: str = PLUGIN_NAME,
                      plugin_version: str = PLUGIN_VERSION, attempts: int = 120) -> dict:
    """旧 ticket 流程：轮询换取凭据。"""
    client = await get_client()
    for _ in range(attempts):
        response = await client.get(CREDENTIAL_ENDPOINT, params={"ticket_id": ticket_id, "secret": secret},
                                    headers={"content-type": "application/json;charset=UTF-8",
                                             "plugin-name": plugin_name, "plugin-version": plugin_version},
                                    timeout=15)
        if response.status_code < 400:
            payload = response.json()
            credential = _parse_ticket_payload(payload)
            if credential is not None:
                return credential
        await asyncio.sleep(1)
    raise UpstreamError("codearts login ticket polling timed out", CODE["timeout"])


def _parse_ticket_payload(payload: dict) -> dict | None:
    if not isinstance(payload, dict):
        return None
    credential = payload.get("credential")
    if isinstance(credential, dict):
        return {
            "access_key_id": credential.get("access", credential.get("accessKeyId", "")),
            "secret_access_key": credential.get("secret", credential.get("secretAccessKey", "")),
            "security_token": credential.get("securitytoken", credential.get("securityToken", "")),
            "expires_at": credential.get("expires_at", credential.get("expiresAt", "")),
            "domain_id": payload.get("domain_id", ""),
            "user_id": payload.get("user_id", ""),
            "user_name": payload.get("user_name", ""),
        }
    result = payload.get("result")
    if isinstance(result, dict):
        return {
            "access_key_id": result.get("accessKeyId", ""),
            "secret_access_key": result.get("secretAccessKey", ""),
            "security_token": result.get("securityToken", ""),
            "expires_at": result.get("expiration", result.get("expiresAt", "")),
        }
    return None


async def run_oauth_login(*, open_browser: bool = True, timeout_s: int = LOGIN_TIMEOUT_S) -> dict:
    """跑一次完整的新式 OAuth 浏览器登录，返回凭据 dict。"""
    verifier, challenge = generate_pkce_pair()
    private_key, public_jwk, private_jwk = generate_dpop_keypair()
    ticket_id = secrets.token_hex(16)
    result: dict = {"credential": None, "error": None}
    done = asyncio.Event()
    state: dict[str, Any] = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            _, target, _ = (request_line.split(" ") + ["", "", ""])[:3]
            from urllib.parse import parse_qs, urlsplit
            query = parse_qs(urlsplit(target).query)
            response = "HTTP/1.1 307 Temporary Redirect\r\nContent-Length: 0\r\n\r\n"
            try:
                writer.write(response.encode("latin-1"))
                await writer.drain()
            finally:
                writer.close()
            code = (query.get("code") or [None])[0]
            secret = (query.get("secret") or [None])[0]
            if code:
                state["code"] = code
            elif secret:
                state["secret"] = secret
            done.set()
        except Exception:  # noqa: BLE001
            done.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    if port < 10000:
        server.close()
        await server.wait_closed()
        server = await asyncio.start_server(handle, "127.0.0.1", secrets.randbelow(55535) + 10000)
        port = server.sockets[0].getsockname()[1]

    login_url = build_oauth_login_url(port, challenge, ticket_id)
    if open_browser:
        _open_external(login_url)
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        raise UpstreamError("codearts login timed out waiting for the browser callback", CODE["timeout"])
    finally:
        server.close()
        with __import__("contextlib").suppress(Exception):
            await server.wait_closed()

    if state.get("code"):
        payload = await _exchange_token(**{
            "client_id": CLIENT_ID, "code": state["code"], "code_verifier": verifier,
            "grant_type": "authorization_code", "redirect_uri": f"http://127.0.0.1:{port}{REDIRECT_PATH}",
        })
        return credential_from_token_response(payload, code_verifier=verifier, private_jwk=private_jwk)
    if state.get("secret"):
        return await poll_ticket(ticket_id, state["secret"])
    raise UpstreamError("codearts login callback carried no code or secret", CODE["credential"])


def _open_external(url: str) -> bool:
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


async def refresh_credential(credential: dict) -> dict:
    """用 refresh_token 换取新凭据（华为 STS 会作废旧 refresh_token）。"""
    refresh_token = credential.get("refresh_token")
    verifier = credential.get("code_verifier")
    jwk = credential.get("dpop_private_key_jwk")
    if not (refresh_token and verifier and jwk):
        raise UpstreamError("codearts credential cannot be refreshed (missing refresh_token / code_verifier / dpop key)",
                            CODE["credential"])
    payload = await _exchange_token(**{
        "client_id": CLIENT_ID, "code_verifier": verifier,
        "grant_type": "refresh_token", "refresh_token": refresh_token,
    })
    fresh = credential_from_token_response(payload, code_verifier=verifier, private_jwk=jwk)
    for key in ("domain_id", "user_id", "user_name"):
        if credential.get(key):
            fresh[key] = credential[key]
    return fresh


# ── 模型目录 ────────────────────────────────────────────────────────────────

def normalize_model_id(model_id: str) -> str:
    import re
    return re.sub(r"-\d{4}$", "", str(model_id or ""))


async def _signed_get(credential: dict, url: str, extra_unsigned: dict[str, str] | None = None) -> Any:
    client = await get_client()
    signed = sign_request(ak=credential["access_key_id"], sk=credential["secret_access_key"],
                          method="GET", url=url, headers={"content-type": "application/json"},
                          body=b"", security_token=credential.get("security_token"))
    if extra_unsigned:
        signed.update(extra_unsigned)
    response = await client.get(url, headers=signed, timeout=MODELS_TIMEOUT_S)
    if response.status_code >= 400:
        raise UpstreamError(f"codearts model listing failed: HTTP {response.status_code}", CODE["server"],
                            status=response.status_code)
    return response.json()


async def fetch_models(credential: dict) -> dict:
    """返回 ``{"models": [...], "benefit": [...]}``。"""
    models: list[dict] = []
    benefit: list[str] = []
    seen: set[str] = set()
    try:
        config = await _signed_get(credential, OPENGW_GATEWAY_CONFIG_URL)
        for row in (config.get("result") or {}).get("models") or []:
            raw = row.get("model_id")
            if isinstance(raw, str) and normalize_model_id(raw) == raw:
                benefit.append(raw)
            _add_model(models, seen, row)
    except Exception:  # noqa: BLE001
        pass
    try:
        builtin = await _signed_get(credential, SNAP_MODEL_BUILTIN_URL, {
            "Content-Type": "application/json", "Agent-Type": "PromptCenter", "X-Language": "zh-cn",
        })
        for row in builtin.get("builtinModels") or []:
            _add_model(models, seen, row)
    except Exception:  # noqa: BLE001
        pass
    if not models:
        models = [{"id": m, "name": m} for m in DEFAULT_MODELS]
    if not benefit:
        benefit = list(BENEFIT_FALLBACK)
    return {"models": models, "benefit": benefit}


def _add_model(models: list[dict], seen: set[str], row: dict) -> None:
    raw_id = row.get("model_id") if isinstance(row, dict) else None
    if not isinstance(raw_id, str) or raw_id == "":
        return
    model_id = normalize_model_id(raw_id)
    if "-VL-" in model_id or model_id.endswith("-VL"):
        return
    if model_id in seen:
        return
    seen.add(model_id)
    name = normalize_model_id(row.get("model_name") or "") or model_id
    models.append({"id": model_id, "name": name})


# ── 推理 ────────────────────────────────────────────────────────────────────

def _is_benefit(model_id: str, benefit: set[str]) -> bool:
    return model_id in benefit


async def stream(body: dict, credential: dict, *, catalog: dict | None = None,
                 on_refresh: Callable[[dict], None] | None = None) -> AsyncIterator[dict]:
    """POST 一轮 chat/completions 并以内部 chunk 产出。"""
    model_id = body.get("model", "")
    benefit = set((catalog or {}).get("benefit") or BENEFIT_FALLBACK)
    payload = dict(body)
    payload.setdefault("stream", True)
    payload["prompt_cache_key"] = payload.get("user") or payload.get("prompt_cache_key") or ""
    payload["include"] = ["reasoning.encrypted_content"]
    payload["reasoning_summary"] = "auto"
    payload["tool_stream"] = True
    payload["max_tokens"] = int(payload.get("max_tokens") or MAX_TOKENS_DEFAULT)
    if payload.pop("reasoning_effort", None) == "off":
        payload["thinking"] = {"type": "disabled"}

    headers = {"Content-Type": "application/json", "lang": "en",
               "Chat-Id": secrets.token_hex(16), "Session-Id": secrets.token_hex(16)}
    if _is_benefit(model_id, benefit):
        headers["maas_type"] = "benefit"

    channel = create_channel()
    client = await get_client()

    async def produce():
        try:
            nonlocal credential
            url = f"{CHAT_API_BASE}/chat/completions"
            data = json.dumps(payload).encode("utf-8")
            signed = sign_request(ak=credential["access_key_id"], sk=credential["secret_access_key"],
                                  method="POST", url=url, headers=headers, body=data,
                                  security_token=credential.get("security_token"))
            async with client.stream("POST", url, headers=signed, content=data,
                                     timeout=httpx.Timeout(connect=15.0, read=600.0, write=60.0, pool=15.0)) as response:
                if response.status_code in (401, 403):
                    refreshed = await refresh_credential(credential)
                    credential = refreshed
                    if on_refresh is not None:
                        on_refresh(refreshed)
                    signed = sign_request(ak=credential["access_key_id"], sk=credential["secret_access_key"],
                                          method="POST", url=url, headers=headers, body=data,
                                          security_token=credential.get("security_token"))
                    response = await client.send(
                        client.build_request("POST", url, headers=signed, content=data), stream=True)
                if response.status_code >= 400:
                    text = (await response.aread()).decode("utf-8", "replace")
                    raise UpstreamError(f"codearts: HTTP {response.status_code} {text[:200]}", CODE["server"],
                                        status=response.status_code)
                head = await read_head(response.aiter_bytes(), 4096, 600.0)
                shape = sniff_body(head.text)
                if shape == "empty":
                    raise UpstreamError("codearts: empty response", CODE["empty"])
                if shape == "sse":
                    await read_sse(_replay(head), channel.push, 600.0)
                else:
                    text = (await _read_remainder(head)).decode("utf-8", "replace")
                    try:
                        parsed = json.loads(text)
                    except ValueError:
                        raise UpstreamError("codearts: unexpected non-stream response", CODE["server"])
                    if parsed.get("error_code"):
                        raise UpstreamError(f"codearts: {parsed.get('error_msg')}", CODE["server"])
                    channel.push(json.dumps(parsed))
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


CHANNEL_ID = "codearts"

#: 渠道模块约定：``run_login`` 完成一次浏览器登录并返回凭据。
run_login = run_oauth_login
