"""CVar 索引：把 .data 里所有"指向 convar 对象"的槽扫出来，按名字建索引。

## 为什么需要这个模块

`dwSensitivity` / `dwGameTypes` 这类偏移，本质是"某个全局槽里存着一个
convar 对象的指针"。传统做法是找代码交叉引用再猜，但那条路会翻车
（`dwGameTypes` 的基准表就写成过一个"引用 56 次、但其实指向静态跳转表"
的地址）。

真正的决定性判据是 **对象自己带着名字**：

    slot(.data)  --[+0x00]-->  char* name          "sensitivity"
                 --[+0x20]-->  char* description   "Mouse sensitivity."
                 --[+0x58]-->  T     value         0.83f / 1 (int)

于是这个模块反过来做：**先把所有 convar 扫出来建字典，再按名字取槽**。
名字对上就是要的偏移，不需要任何基准、不需要猜测、不受版本平移影响。

## 实测布局（client.dll / matchmaking.dll 通用）

    +0x00  char*  名字（ASCII，可能带 1~3 字节对齐全零）
    +0x20  char*  描述
    +0x58  T      当前值（float 或 int，看类型）

只用 +0x00 / +0x20 / +0x58 这三个位置 —— 之后的字段因 convar 类型而异
（int 型在 +0x5C 还有别的东西），不能当成通用布局。
"""
from __future__ import annotations

import struct

# 指针合法性区间：低于 0x10000 是空指针/小整数，高于 0x7FFF_FFFF_FFFF 是内核地址
PTR_LO, PTR_HI = 0x10000, 0x7FFF_FFFF_FFFF

# convar 名字的合法字符集（CS2 里全是小写字母、数字、下划线）
_NAME_CHARS = set(b"abcdefghijklmnopqrstuvwxyz0123456789_")


def is_ptr(v) -> bool:
    return v is not None and PTR_LO < v < PTR_HI


class Reader:
    """把 GameProcess / verify_all39 里的 Proc 统一成 rd()+q() 两个方法。

    两种对象的方法名不一样（一个叫 read、一个叫 rd），包一层就不用到处判断。
    """

    def __init__(self, proc):
        self.proc = proc
        self._rd = getattr(proc, "rd", None) or getattr(proc, "read")

    def rd(self, addr: int, n: int):
        return self._rd(addr, n)

    def q(self, addr: int):
        b = self.rd(addr, 8)
        return None if b is None else struct.unpack("<Q", b)[0]

    def u32(self, addr: int):
        b = self.rd(addr, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    def i32(self, addr: int):
        b = self.rd(addr, 4)
        return None if b is None else struct.unpack("<i", b)[0]

    def f32(self, addr: int):
        b = self.rd(addr, 4)
        return None if b is None else struct.unpack("<f", b)[0]


def read_name(r, ptr: int, maxlen: int = 48) -> str | None:
    """从 ptr 读一个 convar 名字；带 0~3 字节对齐容错。"""
    if not is_ptr(ptr):
        return None
    raw = r.rd(ptr, maxlen)
    if not raw:
        return None
    for d in range(4):
        b = raw[d:]
        end = b.find(b"\x00")
        if end < 0:
            continue
        s = b[:end]
        if not (2 <= len(s) <= 40):
            continue
        if not all(c in _NAME_CHARS for c in s):
            continue
        try:
            return s.decode("ascii")
        except UnicodeDecodeError:
            continue
    return None


def scan_range(r, base: int, lo: int, hi: int, maxlen: int = 48,
               chunk: int = 1 << 20) -> dict[str, dict]:
    """扫 [base+lo, base+hi) 区间，返回 {名字: {slot, obj, name}}。

    只做**两级确认**，不做全量语义判断（那太慢）：
      槽值 → 是指针 → 它指向的第一个 qword 也是指针 → 那个指针处是可读名字。
    这两级就能把"静态跳转表"和"真 convar"分得干干净净 —— 跳转表的第一个
    qword 是代码地址，代码段里不会有 "a-z0-9_" 组成的可读串。
    """
    out: dict[str, dict] = {}
    addr = base + lo
    end = base + hi
    while addr < end:
        n = min(chunk, end - addr)
        n -= n % 8
        if n <= 0:
            break
        raw = r.rd(addr, n)
        if not raw:
            addr += n
            continue
        for off in range(0, len(raw) - 7, 8):
            (v,) = struct.unpack_from("<Q", raw, off)
            if not is_ptr(v):
                continue
            name_ptr = r.q(v)
            if not is_ptr(name_ptr):
                continue
            nm = read_name(r, name_ptr, maxlen)
            if not nm:
                continue
            rva = addr - base + off
            prev = out.get(nm)
            if prev is None or rva < prev["slot"]:
                out[nm] = {"slot": rva, "obj": v, "name": nm}
        addr += len(raw)
    return out


def value(r, entry: dict):
    """读 convar 当前值，返回 (as_int, as_float)。"""
    o = entry["obj"] + 0x58
    raw = r.rd(o, 4)
    if not raw:
        return None, None
    return struct.unpack("<i", raw)[0], struct.unpack("<f", raw)[0]


def describe(r, entry: dict, limit: int = 72) -> str:
    """对象的可读描述 —— 用来在报告里证明"名字真是从内存读出来的"。"""
    p = r.q(entry["obj"] + 0x20) if hasattr(r, "q") else None
    if not is_ptr(p):
        return ""
    raw = r.rd(p, limit)
    if not raw:
        return ""
    s = raw.split(b"\x00")[0]
    try:
        return s.decode("mbcs", "replace")
    except Exception:
        return ""
