"""活进程访问：打开 CS2、定位 client.dll、分块读内存。

两个必须处理的现实：
  * 模块基址每次启动都变（ASLR），偏移一律按 RVA 算，基址只在这一层补上。
  * .data 里有大段 .bss（未初始化），读出来是 0；读不到和读到 0 要分开。
    read() 返回 None 表示读失败（页不可读），返回全零 bytes 才是真的 0。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as w
from dataclasses import dataclass

import pefile

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

k32.OpenProcess.restype = w.HANDLE
k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.CloseHandle.argtypes = [w.HANDLE]
k32.GetProcessTimes.argtypes = [
    w.HANDLE, ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME),
    ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME),
]
k32.GetProcessTimes.restype = w.BOOL
k32.ReadProcessMemory.argtypes = [
    w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
k32.ReadProcessMemory.restype = w.BOOL
k32.VirtualQueryEx.argtypes = [
    w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
]
k32.VirtualQueryEx.restype = ctypes.c_size_t


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
        ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
        ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", w.DWORD), ("hModule", w.HMODULE),
        ("szModule", w.CHAR * 256), ("szExePath", w.CHAR * MAX_PATH),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", w.DWORD),
        ("cntThreads", w.DWORD), ("th32ParentProcessID", w.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", w.DWORD),
        ("szExeFile", w.CHAR * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", w.DWORD), ("RegionSize", ctypes.c_size_t),
        ("State", w.DWORD), ("Protect", w.DWORD), ("Type", w.DWORD),
    ]


MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


@dataclass
class ProcInfo:
    pid: int
    exe: str
    create_time: int = 0   # 进程创建时间（FILETIME，100ns 单位）


def _proc_create_time(pid: int) -> int:
    """取进程创建时间。用于识别 PID 复用 —— PID 会被系统回收再分配。

    读不到就返回 0（不影响主流程，只是失去这项校验）。
    """
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return 0
    try:
        c = w.FILETIME(); e = w.FILETIME(); k = w.FILETIME(); u = w.FILETIME()
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                   ctypes.byref(k), ctypes.byref(u)):
            return 0
        return (c.dwHighDateTime << 32) | c.dwLowDateTime
    finally:
        k32.CloseHandle(h)


def list_processes(name_keyword: str = "cs2") -> list[ProcInfo]:
    """按可执行名模糊匹配进程。cs2.exe 是 CS2 的正式进程名。"""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    out: list[ProcInfo] = []
    if snap == w.HANDLE(-1).value or not snap:
        return out
    try:
        e = PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32First(snap, ctypes.byref(e))
        while ok:
            exe = e.szExeFile.decode("ascii", "replace")
            if name_keyword.lower() in exe.lower():
                out.append(ProcInfo(e.th32ProcessID, exe,
                                    _proc_create_time(e.th32ProcessID)))
            ok = k32.Process32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def _proc_exe_name(pid: int) -> str:
    """按 PID 反查可执行名（用于报错时说清"这个 PID 现在是哪个程序"）。"""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == w.HANDLE(-1).value or not snap:
        return ""
    try:
        e = PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32First(snap, ctypes.byref(e))
        while ok:
            if e.th32ProcessID == pid:
                return e.szExeFile.decode("ascii", "replace")
            ok = k32.Process32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return ""


def pick_process(name_keyword: str = "cs2", pid: int | None = None) -> ProcInfo:
    """决定要连哪个进程。给 pid 就校验它，不给就自动挑。

    为什么不能"给了 pid 就用"：
      PID 是内核循环复用的编号。上次跑的时候 cs2.exe 是 16044，游戏关掉再
      重开，16044 可能已经是别的程序（甚至被别的进程占用）。直接 OpenProcess
      要么失败，要么**成功但连着别人** —— 后者更坏：读出来一堆垃圾，
      然后所有判据"全部失败"，看起来像偏移算错了，其实是连错进程。

    所以校验两件事：这个 PID 现在还是 cs2 吗、进程还在不在。
    名字对不上就拒绝，不"凑合着用"。
    """
    procs = list_processes(name_keyword)
    if pid:
        hit = next((p for p in procs if p.pid == pid), None)
        if hit:
            return hit
        other = _proc_exe_name(pid)
        if other:
            raise LookupError(
                "PID %d 现在是 %s，不是 %s.exe —— 这个编号已经被系统回收分给别人了。\n"
                "  游戏重开过的话 PID 一定会变，上次的旧值不能再用。\n"
                "  处理：去掉 --pid 直接跑，程序会自己找当前的 cs2.exe。"
                % (pid, other, name_keyword))
        raise LookupError(
            ("PID %d 找不到：既没有 cs2.exe 占用它，也没有任何进程占用它。\n"
             "  游戏可能已经退出。\n"
             "  处理：先开游戏；只想看静态就加 --no-live 或 --offline。") % pid)
    if not procs:
        raise LookupError(
            "没找到运行中的 cs2.exe。\n"
            "  游戏没启动 → 先开游戏，等主菜单出来再跑；\n"
            "  只想看静态 → 加 --no-live（1 秒）或 --offline（约 9 秒）。")
    if len(procs) > 1:
        # 多个 cs2.exe 极罕见（一般只有一个），真出现就挑最晚启动的那个
        procs.sort(key=lambda p: p.create_time, reverse=True)
    return procs[0]


class GameProcess:
    """一个打开的 CS2 进程。当作上下文对象用，用完 close()。"""

    def __init__(self, pid: int):
        self.pid = pid
        self.h = k32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not self.h:
            raise OSError(
                "OpenProcess(pid=%d) 失败, GetLastError=%d" % (pid, ctypes.get_last_error())
            )
        self.base = 0
        self.size = 0
        self.mods: dict[str, tuple[int, int]] = {}
        self._locate_client_dll()

    # ---------------------------------------------------------------- 模块
    def _locate_client_dll(self) -> None:
        snap = k32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid
        )
        if snap == w.HANDLE(-1).value or not snap:
            raise OSError("CreateToolhelp32Snapshot(modules) 失败")
        try:
            e = MODULEENTRY32()
            e.dwSize = ctypes.sizeof(e)
            ok = k32.Module32First(snap, ctypes.byref(e))
            while ok:
                nm = e.szModule.decode("ascii", "replace").lower()
                # 顺手把所有模块都记下来 —— dwGameTypes 在 matchmaking.dll 里，
                # 只认 client.dll 会漏掉一半目标。
                self.mods[nm] = (ctypes.cast(e.modBaseAddr, ctypes.c_void_p).value,
                                 e.modBaseSize)
                if nm == "client.dll" and not self.base:
                    self.base = self.mods[nm][0]
                    self.size = self.mods[nm][1]
                ok = k32.Module32Next(snap, ctypes.byref(e))
        finally:
            k32.CloseHandle(snap)
        if self.base:
            return
        raise LookupError(
            "进程里没有 client.dll —— 可能还在启动、或没进图。"
            "等主菜单出来（最好进一张图）再重跑。"
        )

    def module(self, name: str) -> tuple[int, int] | None:
        """按模块名取 (base, size)，名字大小写不敏感。"""
        return self.mods.get(name.lower())

    def verify_against(self, exe_path: str) -> tuple[bool, str]:
        """活模块的 PE 头与磁盘文件是否一致（判断是否同一版本）。

        **踩过的坑**：第一版拿 `hdr[0x3C:0x40]` 当入口点比较 —— 那不是入口点，
        是 `e_lfanew`（PE 头在文件里的偏移，恒为 0x160 之类）。
        正确做法：先按 e_lfanew 定位 NT 头，再读
          * 文件头的 TimeDateStamp（编译时间戳，最稳的版本指纹）
          * 可选头的 AddressOfEntryPoint
        """
        hdr = self.read(self.base, 0x1000)
        if not hdr or hdr[:2] != b"MZ":
            return False, "活模块头读不到或不是 MZ"
        try:
            pe = pefile.PE(exe_path, fast_load=True)
        except Exception as exc:
            return False, "读磁盘 PE 失败: %s" % exc
        try:
            if self.size != pe.OPTIONAL_HEADER.SizeOfImage:
                return False, "SizeOfImage 不一致: 活=%#x 盘=%#x" % (
                    self.size, pe.OPTIONAL_HEADER.SizeOfImage)
            e_lfanew = int.from_bytes(hdr[0x3C:0x40], "little")
            if e_lfanew <= 0 or e_lfanew + 0x30 > len(hdr):
                return False, "e_lfanew 异常: %#x" % e_lfanew
            nt = hdr[e_lfanew:e_lfanew + 0x30]
            if nt[:4] != b"PE\0\0":
                return False, "活模块 NT 签名不对"
            # NT 头布局：签名 4 + FileHeader 20 = 0x18，之后是 OptionalHeader。
            #   TimeDateStamp     在 NT+0x08（FileHeader 内）
            #   AddressOfEntryPoint 在 NT+0x18+0x10 = NT+0x28（OptionalHeader 内）
            # 第一版把 NT+0x14 当入口点，那是 FileHeader 的 SizeOfOptionalHeader，
            # 读出来恒是垃圾 → 版本校验永远报"不一致"（踩过）。
            ts_live = int.from_bytes(nt[0x08:0x0C], "little")
            ts_disk = pe.FILE_HEADER.TimeDateStamp
            if ts_live != ts_disk:
                return False, "编译时间戳不一致: 活=%#x 盘=%#x" % (ts_live, ts_disk)
            ep_live = int.from_bytes(nt[0x28:0x2C], "little")
            ep_disk = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if ep_live != ep_disk:
                return False, "入口点不一致: 活=%#x 盘=%#x" % (ep_live, ep_disk)
            return True, "一致 (SizeOfImage=%#x, TS=%#x, EP=%#x)" % (
                self.size, ts_live, ep_live)
        finally:
            pe.close()

    # ---------------------------------------------------------------- 读
    def read(self, addr: int, n: int) -> bytes | None:
        """读失败（页不可读）返回 None；成功返回恰好 n 字节。"""
        if n <= 0:
            return b""
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t()
        if not k32.ReadProcessMemory(
            self.h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)
        ):
            return None
        if got.value != n:
            return None
        return buf.raw[: got.value]

    def read_rva(self, rva: int, n: int) -> bytes | None:
        return self.read(self.base + rva, n)

    def read_chunked(self, rva: int, n: int, chunk: int = 0x100000) -> bytes:
        """大块读，读不到的页填 0 并记下来。

        返回的 bytes 长度恒等于 n —— 下游可以安全地用 numpy 切片，
        但必须知道哪些区间其实是"读失败填的 0"（见 unreadable）。
        """
        out = bytearray(n)
        self.unreadable: list[tuple[int, int]] = []
        pos = 0
        while pos < n:
            take = min(chunk, n - pos)
            got = self.read_rva(rva + pos, take)
            if got is None:
                # 退化为按页读，把坏页单独标出来
                for page in range(pos, pos + take, 0x1000):
                    take2 = min(0x1000, n - page)
                    got2 = self.read_rva(rva + page, take2)
                    if got2 is None:
                        self.unreadable.append((rva + page, take2))
                    else:
                        out[page : page + take2] = got2
            else:
                out[pos : pos + take] = got
            pos += take
        return bytes(out)

    def regions(self) -> list[tuple[int, int, int]]:
        """枚举已提交、可读的区域：(base, size, protect)。"""
        out = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        limit = 0x7FFFFFFF0000
        while addr < limit:
            r = k32.VirtualQueryEx(
                self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not r:
                break
            base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
            size = mbi.RegionSize
            if mbi.State == MEM_COMMIT and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)):
                out.append((base, size, mbi.Protect))
            nxt = base + size
            if nxt <= addr:
                break
            addr = nxt
        return out

    # ---------------------------------------------------------------- 上下文
    def close(self) -> None:
        if getattr(self, "h", None):
            k32.CloseHandle(self.h)
            self.h = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
