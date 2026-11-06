"""RTTI / vtable 收割：给"这个指针指向什么类"提供硬证据。

MSVC 的 x64 RTTI 布局（相对 vtable 起始地址）：
    vt - 8     -> ptr 指向 CompleteObjectLocator
    col + 0x00  uint32 signature（必须是 1）
    col + 0x04  uint32 offset
    col + 0x08  uint32 cdOffset
    col + 0x0C  uint32 typeDescriptor（RVA，相对模块基址）
    col + 0x10  uint32 classDescriptor
    col + 0x14  uint32 self
    td  + 0x00  vftable ptr
    td  + 0x08  spare
    td  + 0x10  修饰名 ".?AVC_CSPlayerPawn@@" 之类

用途：验证门里要知道"实体表里的指针是不是真的 C_CSPlayerPawn"，
      靠类名比靠字段猜测可靠得多。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .pe import Image

TPI = 1


@dataclass
class ClassInfo:
    vtable_rva: int
    decorated: str
    name: str | None

    @property
    def is_c_entity(self) -> bool:
        return bool(self.name and self.name.startswith("C_"))


def decode_msvc_name(decorated: str) -> str | None:
    """'.?AVC_CSPlayerPawn@@' -> 'C_CSPlayerPawn'。

    只处理最常见的 3 种前缀；模板实例化的名字保留原样（也有用）。
    """
    if not decorated.startswith(".?A"):
        return None
    body = decorated[4:]
    if not body or body[0] not in "VU":
        return None
    body = body[1:]
    # 去掉尾部 '@@' 以及后面可能的修饰
    body = body.split("@@")[0]
    return body or None


def type_name_at(img: Image, col_rva: int) -> str | None:
    sig, _off, _cd, td, _cd2 = struct.unpack_from("<IIIII", img.read(col_rva, 0x14))
    if sig != TPI or td == 0 or td >= img.size_of_image:
        return None
    dec = img.cstr(td + 16, 300)
    return decode_msvc_name(dec) if dec else None


def scan_vtables(img: Image, lo: int, hi: int, step: int = 8) -> dict[str, list[int]]:
    """扫 [lo, hi) 里所有像 vtable 首地址的位置，收成 name -> [vtable_rva]。"""
    out: dict[str, list[int]] = {}
    buf = img.read(lo, hi - lo)
    for i in range(0, len(buf) - 8, step):
        rva = lo + i
        p = struct.unpack_from("<Q", buf, i)[0]
        col = img.to_rva(p)
        if col is None or not (0 < col < img.size_of_image - 0x18):
            continue
        nm = type_name_at(img, col)
        if nm:
            out.setdefault(nm, []).append(rva)
    return out


def vtable_name(img: Image, vtable_va: int) -> str | None:
    """给定一个活进程里读到的 vptr（VA），返回它所属类名。"""
    rva = img.to_rva(vtable_va)
    if rva is None or rva < 8:
        return None
    col_ptr = img.q(rva - 8)
    col = img.to_rva(col_ptr)
    if col is None:
        return None
    return type_name_at(img, col)
