"""13 个账号渠道 + 两条免密车道的注册表。

每条记录形如：
``{id, name, vendor, login, domains, implemented}``。

``implemented=True`` 表示该渠道在本移植版中可用（匿名免费车道、Kilo 免费池已完整落地）。
其余渠道的**登录流程**逐家移植后置为 True；在置为 True 之前，它们不会出现在模型列表，
也不会发起任何请求。
"""

from __future__ import annotations

CHANNELS: list[dict] = [
    {"id": "anonymous", "name": "匿名免费车道", "vendor": "OpenCode Zen", "login": "none",
     "domains": ["opencode.ai"], "implemented": True},
    {"id": "kilo", "name": "Kilo 免费池", "vendor": "Kilo AI", "login": "none",
     "domains": ["api.kilo.ai"], "implemented": True},
    {"id": "codearts", "name": "CodeArts", "vendor": "华为云", "login": "browser",
     "domains": ["huaweicloud.com"], "implemented": True},
    {"id": "buddy", "name": "CodeBuddy", "vendor": "腾讯", "login": "browser",
     "domains": ["copilot.tencent.com"], "implemented": True},
    {"id": "workbuddy", "name": "WorkBuddy", "vendor": "腾讯（国际版）", "login": "browser",
     "domains": ["www.workbuddy.ai"], "implemented": True},
    {"id": "lobsterai", "name": "LobsterAI", "vendor": "有道", "login": "browser",
     "domains": ["youdao.com"], "implemented": True},
    {"id": "qoder", "name": "Qoder", "vendor": "阿里系", "login": "device-code",
     "domains": ["qoder.com", "openapi.qoder.com.cn", "gateway.qoder.com.cn"], "implemented": True},
    {"id": "qodercn", "name": "Qoder 中国版", "vendor": "阿里系", "login": "device-code",
     "domains": ["qoder.cn"], "implemented": True},
    {"id": "trae", "name": "TRAE", "vendor": "字节", "login": "browser",
     "domains": ["trae.ai"], "implemented": True},
    {"id": "cline", "name": "Cline", "vendor": "Cline", "login": "device-code",
     "domains": ["api.workos.com", "cline.bot"], "implemented": True},
    {"id": "loomy", "name": "Loomy", "vendor": "讯飞", "login": "sms",
     "domains": ["xfyun.cn"], "implemented": True},
    {"id": "raccoon", "name": "Raccoon Work", "vendor": "商汤", "login": "qr/sms",
     "domains": ["sensetime.com"], "implemented": True},
    {"id": "minimax", "name": "MiniMax Code", "vendor": "MiniMax", "login": "device-code",
     "domains": ["minimax.io", "minimaxi.com"], "implemented": True},
    {"id": "zcode", "name": "ZCode", "vendor": "智谱", "login": "device-code",
     "domains": ["z.ai", "bigmodel.cn"], "implemented": True},
    {"id": "gemini", "name": "Gemini", "vendor": "Google Code Assist", "login": "browser",
     "domains": ["accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"], "implemented": True},
]

_BY_ID = {c["id"]: c for c in CHANNELS}


def get_channel(channel_id: str) -> dict | None:
    return _BY_ID.get(channel_id)


def list_channels(pool=None) -> list[dict]:
    """列出全部渠道；若给出账号池，附带账号数量与启用数量。"""
    out = []
    for channel in CHANNELS:
        row = dict(channel)
        if pool is not None:
            accounts = pool.list_by_provider(channel["id"])
            row["accounts"] = len(accounts)
            row["enabledAccounts"] = sum(1 for a in accounts if a.get("enabled"))
        row["status"] = "ready" if channel["implemented"] else (
            "logged-in" if pool is not None and pool.list_by_provider(channel["id"]) else "pending")
        out.append(row)
    return out


def channel_status(channel_id: str, pool=None) -> dict:
    channel = get_channel(channel_id)
    if channel is None:
        return {"id": channel_id, "status": "unknown"}
    row = dict(channel)
    if pool is not None:
        row["accounts"] = len(pool.list_by_provider(channel_id))
    row["status"] = "ready" if channel["implemented"] else "pending"
    return row
