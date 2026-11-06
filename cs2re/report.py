"""把成品（默认只有 .ofs 偏移表）投递到 `下载目录\\cs2-re\\`。

设计原则：**下载目录里只留一份最新的偏移表**，别的都不放。
之前那版每次扫描都往下载目录塞 `auto-scan-<时间戳>.txt` +
`auto-scan-最新.txt` + `verify-live-*.txt`，跑十次就是二十个文件，
真要的东西反而是最小的那个 `deliver.ofs` —— 全删掉。

需要留终端日志复查时，设环境变量 `CS2RE_REPORT=1` 才会回到老行为
（带时间戳的 txt + 一份 `-最新.txt`）。
输出目录可用 `CS2RE_OUT` 改到别处；`CS2RE_NO_REPORT=1` 完全关掉落盘。
"""
from __future__ import annotations

import datetime
import os
import sys
from contextlib import contextmanager
from pathlib import Path


def _flag(name: str) -> bool:
    return os.environ.get(name, "") in ("1", "true", "yes")


def enabled() -> bool:
    """是否允许往下载目录落盘（成品投递 + 日志）。"""
    return not _flag("CS2RE_NO_REPORT")


def log_enabled() -> bool:
    """是否额外写终端日志 txt。默认关：下载目录只留偏移表一份。"""
    return enabled() and _flag("CS2RE_REPORT")


def out_dir() -> Path:
    r"""下载目录下的 cs2-re 子目录。Windows 上 Downloads 可能被重定向，所以先问系统。"""
    env = os.environ.get("CS2RE_OUT")
    if env:
        p = Path(env)
    else:
        base = None
        try:
            # 用户把"下载"改到 D 盘时，Path.home()/"Downloads" 就是空的
            import winreg
            key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
                v, _ = winreg.QueryValueEx(k, "{374DE290-123F-4565-9164-39C4925E467B}")
            base = Path(os.path.expandvars(v))
        except Exception:
            base = None
        if base is None or not base.parent.exists():
            base = Path.home() / "Downloads"
        p = base / "cs2-re"
    p.mkdir(parents=True, exist_ok=True)
    return p


class Tee:
    """写屏幕 + 留底。保持 isatty/fileno，免得下游代码以为是重定向。"""

    def __init__(self, stream):
        self.stream = stream
        self.buf: list[str] = []

    def write(self, s):
        self.buf.append(s)
        return self.stream.write(s)

    def flush(self):
        self.stream.flush()

    def isatty(self):
        return self.stream.isatty()

    def fileno(self):
        return self.stream.fileno()

    @property
    def encoding(self):
        return getattr(self.stream, "encoding", "utf-8")

    def text(self) -> str:
        return "".join(self.buf)


def save(name: str, text: str) -> Path | None:
    """写终端日志。默认不写 —— 只有 CS2RE_REPORT=1 时才落盘。"""
    if not log_enabled() or not text.strip():
        return None
    d = out_dir()
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    p = d / ("%s-%s.txt" % (name, ts))
    p.write_text(text, encoding="utf-8-sig")     # BOM：记事本双击不乱码
    (d / ("%s-最新.txt" % name)).write_text(text, encoding="utf-8-sig")
    return p


@contextmanager
def capture(name: str, quiet: bool = False):
    """with capture('verify-all39'): ... —— 出了这个块就写文件。

    quiet=True 时不打印路径：被父进程当子进程调起时，那行字会插在父进程
    的表格中间，看着像错乱。
    """
    tee = Tee(sys.stdout)
    old, sys.stdout = sys.stdout, tee
    try:
        yield tee
    finally:
        sys.stdout = old
        p = save(name, tee.text())
        if p is not None and not quiet:
            print("报告 -> %s" % p)


def publish(paths, keep=(".ofs",)) -> list[Path]:
    """把 out\\ 下的成品复制进下载目录。

    keep 是白名单后缀，默认只放 .ofs —— 下载目录只留一份偏移表。
    需要 hpp / json 一起放时显式传 keep=(".ofs", ".hpp", ".json")。
    """
    import shutil
    if not enabled():
        return []
    d = out_dir()
    got = []
    for s in paths:
        s = Path(s)
        if not s.exists() or s.suffix.lower() not in keep:
            continue
        dst = d / s.name
        try:
            shutil.copy2(s, dst)
            got.append(dst)
        except OSError:
            pass
    return got


def prune(d: Path, keep: set[str]) -> list[Path]:
    """删掉下载目录里除 keep 之外的旧产物（只动本工具自己的命名）。"""
    if not enabled() or not d.exists():
        return []
    gone = []
    for f in d.iterdir():
        if not f.is_file() or f.name in keep:
            continue
        # 不要碰主人自己丢进来的东西：只认本工具产出的文件名形状
        stem = f.stem
        if not (
            stem.startswith("auto-scan")
            or stem.startswith("verify-live")
            or stem.startswith("verify-all39")
            or stem.startswith("deliver")
        ):
            continue
        try:
            f.unlink()
            gone.append(f)
        except OSError:
            pass
    return gone
