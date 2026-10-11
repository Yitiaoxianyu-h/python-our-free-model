"""渠道框架：凭据存储、账号池、渠道注册表与 OpenAI 兼容适配器基类。

原版把 13 个账号渠道（CodeArts、CodeBuddy、WorkBuddy、LobsterAI、Qoder 国际版/中国版、
TRAE、Cline、Loomy、Raccoon、MiniMax Code、ZCode、Gemini）以每实例 Worker 隔离挂在
同一个服务端口上，通过 ``provider/model`` 形式的模型 ID 暴露。

本模块落地同样的骨架：
- :class:`CredentialStore`：账号凭据落盘（数据目录内，权限收紧），每个账号一个 ref；
- :class:`AccountPool`：账号条目（启用、模型级限流、永久积分锁定、昵称、优先级）；
- :class:`OpenAICompatChannel`：标准 OpenAI 兼容上游的流式适配器（多数渠道可复用）；
- :func:`registry`：13 个渠道的元数据（厂商、登录形态、产品域名）。

各渠道的**登录流程**（浏览器回调 / 设备码轮询 / 短信验证码 / ZCode 的 chromium 验证码）
在 `registry` 中标记为 ``login="pending"``，逐家移植后置为 ``implemented``。
未被移植的渠道不会出现在模型列表里，也不会发起任何请求。
"""

from .store import AccountPool, CredentialStore
from .base import ChannelProvider, OpenAICompatChannel
from .registry import CHANNELS, channel_status, get_channel, list_channels
from .manager import ChannelManager

__all__ = [
    "AccountPool",
    "CredentialStore",
    "ChannelProvider",
    "OpenAICompatChannel",
    "ChannelManager",
    "CHANNELS",
    "channel_status",
    "get_channel",
    "list_channels",
]
