"""EAC 密封解锁（与上游 ``src/vault.js`` 逐字对齐）。

- 掩码分片：``HKDF-SHA256(seed, salt=pepper, info='shard-mask')`` 生成掩码流，
  与掩码字节逐位异或得到分片原文；
- 密封密钥：``HKDF-SHA256(拼接三片, salt=HKDF_SALT, info=HKDF_INFO, 32)``；
- 载荷：``AES-256-GCM``，AAD ``ofm-eac-desktop/v1``，布局 ``iv(12) | ct | tag(16)``。

解密得到 ``{"v":1,"m":"eac","t":"worker"|"direct","u":<网关地址>,"s":<签名密钥>|"k":<API Key>}``。
明文只在调用帧内存活：不写盘、不落日志、不回显。
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .eac_vault_data import LANE_ANCHOR, LANE_SEAL, LANE_SHARDS

HKDF_DIGEST = hashes.SHA256()
HKDF_SALT = b"ofm-lane-seal/1\x00co-paid\x00desktop-only"
HKDF_INFO = b"seal-open/ aes-256-gcm/ per-request"
SEAL_AAD = b"ofm-eac-desktop/v1"
IV_BYTES = 12
TAG_BYTES = 16
MASK_PEPPER = b"d21f0a5c7be94f13a68d20e4c9b73f58"

#: 本移植的宿主标识（对应上游 detectSealedHost 的 flavor）。
FLAVOR_STANDALONE = "standalone"


def _b64(value: str) -> bytes:
    return base64.b64decode(value)


def unmask_shard(masked_b64: str, seed_b64: str) -> bytes:
    masked = _b64(masked_b64)
    seed = _b64(seed_b64)
    stream = HKDF(algorithm=HKDF_DIGEST, length=len(masked), salt=MASK_PEPPER,
                  info=b"shard-mask").derive(seed)
    return bytes(a ^ b for a, b in zip(masked, stream))


def derive_seal_key(shards: list[bytes]) -> bytes:
    return HKDF(algorithm=HKDF_DIGEST, length=32, salt=HKDF_SALT, info=HKDF_INFO).derive(b"".join(shards))


def open_seal_with(unmasked: list[bytes], packed: bytes) -> dict | None:
    """解开一个密封；任何失败（片被换、字节被改、载荷截断、AAD 不符）都返回 None。"""
    try:
        if any(len(shard) < 16 for shard in unmasked):
            return None
        key = derive_seal_key(unmasked)
        if len(packed) <= IV_BYTES + TAG_BYTES:
            return None
        iv = packed[:IV_BYTES]
        tag = packed[len(packed) - TAG_BYTES:]
        ciphertext = packed[IV_BYTES:len(packed) - TAG_BYTES]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(SEAL_AAD)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        seal = json.loads(plaintext.decode("utf-8"))
        if not isinstance(seal, dict) or seal.get("v") != 1 or seal.get("m") != "eac":
            return None
        base = seal.get("u") if isinstance(seal.get("u"), str) else ""
        from urllib.parse import urlsplit
        parts = urlsplit(base)
        if parts.scheme != "https" or parts.path.rstrip("/") == "":
            return None
        clean_base = base.rstrip("/")
        if seal.get("t") == "worker":
            if not clean_base.endswith("/v1"):
                return None
            secret = seal.get("s")
            if not isinstance(secret, str) or len(secret) < 32:
                return None
            return {"mode": "worker", "base": clean_base, "signingSecret": secret}
        api_key = seal.get("k") if isinstance(seal.get("k"), str) else ""
        if len(api_key) < 20:
            return None
        return {"mode": "direct", "base": clean_base, "apiKey": api_key}
    except Exception:  # noqa: BLE001  任何异常都视为打不开
        return None


def open_seal() -> dict | None:
    rows = [*LANE_SHARDS, LANE_ANCHOR]
    unmasked = [unmask_shard(row["s"], row["w"]) for row in rows]
    return open_seal_with(unmasked, _b64(LANE_SEAL))


def detect_sealed_host(*, env=None, exec_path=None, argv=None, profile_name=None) -> str | None:
    """本移植的宿主判定。

    上游只在两个桌面宿主解锁；本服务本身就是分发给用户的宿主，
    因此这里返回 ``standalone``（保持函数形状与上游一致，便于将来收紧）。
    """
    return FLAVOR_STANDALONE


def unlock_sealed_lane(*, host: dict | None = None) -> dict[str, Any] | None:
    """闸门 + 解锁：返回 ``{mode, base, signingSecret|apiKey, flavor}`` 或 ``None``。"""
    flavor = detect_sealed_host(**(host or {}))
    if flavor is None:
        return None
    opened = open_seal()
    return None if opened is None else {**opened, "flavor": flavor}
