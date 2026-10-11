"""启动器：解析参数、挑选可用端口、启动 uvicorn，并打印 Web UI 地址。

双击 ``start.bat`` 即执行本脚本：黑框会打印 Web UI 地址，
在 Windows Terminal 中按住 Ctrl 点击该地址即可打开网页控制台。
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

import uvicorn

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from ofm import PRODUCT, __version__  # noqa: E402
from ofm.paths import resolve_data_dir  # noqa: E402
from ofm.service import Service  # noqa: E402


def pick_port(host: str, preferred: int) -> int:
    """优先使用指定端口；被占用则向后寻找可用端口（默认端口 18900 常被占）。"""
    for candidate in [preferred, *range(preferred + 1, preferred + 21)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, candidate))
                return candidate
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"{PRODUCT} 独立本地服务")
    parser.add_argument("--port", type=int, default=18900, help="监听端口，默认 18900（占用时自动顺延）")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认 127.0.0.1")
    parser.add_argument("--data-dir", default=None, help="数据目录，默认项目内 data/")
    parser.add_argument("--no-refresh", action="store_true", help="跳过启动刷新；仍可手动刷新与推理")
    parser.add_argument("--probe", action="store_true", help="启动后执行可用性探测（会产生上游请求）")
    return parser.parse_args()


LOCK_NAME = "service.lock"


def _pid_alive(pid: int) -> bool:
    """判断进程是否存活（不依赖第三方库，且绝不误杀进程）。"""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and code.value == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _running_instance(data_dir: str) -> dict | None:
    """同一数据目录已有活跃实例则返回它的信息（与独立服务原版语义一致）。"""
    lock_path = os.path.join(data_dir, LOCK_NAME)
    try:
        with open(lock_path, "r", encoding="utf-8") as handle:
            info = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(info, dict):
        return None
    pid = info.get("pid")
    if isinstance(pid, int) and pid != os.getpid() and _pid_alive(pid):
        return info
    return None


def _write_lock(data_dir: str, url: str) -> str:
    lock_path = os.path.join(data_dir, LOCK_NAME)
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump({"pid": os.getpid(), "url": url}, handle)
    return lock_path


def main() -> None:
    args = parse_args()
    host = args.host
    data_dir = str(resolve_data_dir(args.data_dir))

    running = _running_instance(data_dir)
    if running is not None:
        print("=" * 68, flush=True)
        print(f"  {PRODUCT} 已经在运行了，无需重复启动。", flush=True)
        print(f"  正在运行的实例：{running.get('url', '(未知地址)')}  (PID {running.get('pid')})", flush=True)
        print("", flush=True)
        print(f"  数据目录同一时间只能由一个实例使用：{data_dir}", flush=True)
        print("  请直接打开上面的地址；若要另开一个，请换端口并指定另一个数据目录：", flush=True)
        print("      start.bat --port 18910 --data-dir <另一个目录>", flush=True)
        print("=" * 68, flush=True)
        return

    port = pick_port(host, args.port)
    # 让渠道模块（如 Gemini 的签名缓存）使用同一数据目录。
    os.environ["OFM_HOME"] = data_dir
    service = Service(data_dir=data_dir, host=host, port=port,
                      refresh=not args.no_refresh, probe=args.probe)

    url = f"http://{host}:{port}"
    print("=" * 68, flush=True)
    print(f"  {PRODUCT} {__version__}  —  本地免费模型转发服务", flush=True)
    print("=" * 68, flush=True)
    print(f"  Web UI 控制台:  {url}", flush=True)
    print(f"  OpenAI 兼容地址: {url}/v1", flush=True)
    print(f"  数据目录:       {data_dir}", flush=True)
    print("", flush=True)
    print("  提示：按住 Ctrl 并点击上面的地址即可打开网页控制台。", flush=True)
    print("  关闭此窗口即停止服务（或按 Ctrl+C）。", flush=True)
    print("=" * 68, flush=True)

    lock_path = _write_lock(data_dir, url)
    config = uvicorn.Config(service.app, host=host, port=port, log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
