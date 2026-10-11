"""华为云 API 网关签名（SDK-HMAC-SHA256）。

与原版 `vendor/channel-pack/src/sign.ts` 的算法一致：

    CanonicalRequest = method \\n uri \\n query \\n canonicalHeaders \\n signedHeaders \\n hex(sha256(payload))
    StringToSign     = "SDK-HMAC-SHA256" \\n X-Sdk-Date \\n hex(sha256(CanonicalRequest))
    Signature        = hex(HMAC-SHA256(SecretAccessKey, StringToSign))

``uri`` 不以 ``/`` 结尾时会补一个 ``/``（华为网关要求）。
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

ALGORITHM = "SDK-HMAC-SHA256"


def sdk_date_now() -> str:
    """``20260924T101112Z`` 形式的 X-Sdk-Date。"""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_uri(path: str) -> str:
    value = path or "/"
    return value if value.endswith("/") else f"{value}/"


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    parts = []
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        parts.append((quote(key, safe="-_.~"), quote(value, safe="-_.~")))
    parts.sort()
    return "&".join(f"{k}={v}" for k, v in parts)


def sign_request(*, ak: str, sk: str, method: str, url: str, headers: dict[str, str],
                 body: bytes = b"", security_token: str | None = None) -> dict[str, str]:
    """返回需要附加到请求上的完整头（含 Authorization）。

    ``headers`` 中的键会被参与签名；本函数会自行补上 host / x-sdk-date /
    x-sdk-content-sha256 / x-security-token / authorization。
    """
    parts = urlsplit(url)
    host = parts.netloc
    signed_input = {k.lower(): ("" if v is None else str(v)) for k, v in headers.items()}
    signed_input["host"] = host
    date_stamp = sdk_date_now()
    signed_input["x-sdk-date"] = date_stamp
    payload_hash = _sha256_hex(body)
    signed_input["x-sdk-content-sha256"] = payload_hash
    if security_token:
        signed_input["x-security-token"] = security_token

    names = sorted(signed_input.keys())
    canonical_headers = "".join(f"{name}:{signed_input[name].strip()}\n" for name in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join([
        method.upper(),
        _canonical_uri(parts.path),
        _canonical_query(parts.query),
        canonical_headers + "",
        signed_headers,
        payload_hash,
    ])
    string_to_sign = f"{ALGORITHM}\n{date_stamp}\n{_sha256_hex(canonical_request.encode('utf-8'))}"
    signature = hmac.new(sk.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = dict(headers)
    out["Host"] = host
    out["X-Sdk-Date"] = date_stamp
    out["X-Sdk-Content-Sha256"] = payload_hash
    if security_token:
        out["X-Security-Token"] = security_token
    out["Authorization"] = f"{ALGORITHM} Access={ak}, SignedHeaders={signed_headers}, Signature={signature}"
    return out
