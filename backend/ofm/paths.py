"""数据目录与路径解析。

独立服务不使用任何宿主（DSH）目录：默认数据落在项目内的 ``data/`` 下，
可用环境变量 ``OFM_HOME`` 或启动参数 ``--data-dir`` 覆盖。
"""

from __future__ import annotations

import os
from pathlib import Path

# backend/ofm/paths.py -> backend/ofm -> backend -> 项目根
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
FRONTEND_DIR = PROJECT_ROOT / "frontend"


def resolve_data_dir(override: str | os.PathLike[str] | None = None) -> Path:
    """返回绝对数据目录，并确保其存在。"""
    if override is not None and str(override).strip() != "":
        target = Path(override).expanduser().resolve()
    else:
        from_env = os.environ.get("OFM_HOME")
        target = Path(from_env).expanduser().resolve() if from_env and from_env.strip() else DEFAULT_DATA_DIR
    target.mkdir(parents=True, exist_ok=True)
    return target


DATA_DIR_NAME = ""
