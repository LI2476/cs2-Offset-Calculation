"""PE 装载与镜像重建。

关键点（这一版踩过的坑，别改坏）：
  * .data 的 SizeOfRawData 只有 0x1ab200，而 VirtualSize 是 0x5e4c2c
    —— 多出来的是 .bss，磁盘上没有内容，运行时才分配。
  * 所以"静态读某个 RVA 得到全零"不等于"这个槽位不存在"，
    只说明它落在 bss 里，必须去活进程读。
    本模块用 is_raw_backed() 明确区分，别让下游把 0 当答案。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import pefile


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int
    chars: int
    data: bytes = b""

    @property
    def vend(self) -> int:
        return self.va + self.vsize

    @property
    def raw_end(self) -> int:
        """文件里有真实内容的最后 RVA（超出即 bss）。"""
        return self.va + min(self.vsize, self.raw_size)

    def __contains__(self, rva: int) -> bool:
        return self.va <= rva < self.vend


class Image:
    """把 PE 摊平成"RVA -> 字节"的稀疏数组。

    data[rva] 只在文件真有内容时可读；bss 区域读出 0，但要先问
    is_raw_backed()，否则会把"未初始化"误判成"值就是 0"。
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        pe = pefile.PE(str(self.path), fast_load=True)
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        self.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.timestamp = int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0)
        self.sections: list[Section] = [
            Section(
                name=s.Name.decode("ascii", "replace").rstrip("\x00"),
                va=s.VirtualAddress,
                vsize=s.Misc_VirtualSize,
                raw_ptr=s.PointerToRawData,
                raw_size=s.SizeOfRawData,
                chars=s.Characteristics,
                data=s.get_data(),
            )
            for s in pe.sections
        ]
        self._buf = bytearray(self.size_of_image)
        self._raw_ranges: list[tuple[int, int]] = []
        for s in self.sections:
            n = min(s.vsize, s.raw_size)
            if n <= 0:
                continue
            self._buf[s.va : s.va + n] = s.data[:n]
            self._raw_ranges.append((s.va, s.va + n))
        pe.close()

    # ---------------------------------------------------------------- 基础
    def section_of(self, rva: int) -> Section | None:
        for s in self.sections:
            if rva in s:
                return s
        return None

    def is_raw_backed(self, rva: int) -> bool:
        """该 RVA 在磁盘文件里有真实字节（不是 bss）。"""
        return any(lo <= rva < hi for lo, hi in self._raw_ranges)

    def read(self, rva: int, n: int) -> bytes:
        end = min(rva + n, self.size_of_image)
        if rva < 0 or rva >= end:
            return b""
        return bytes(self._buf[rva:end])

    def q(self, rva: int) -> int:
        b = self.read(rva, 8)
        return struct.unpack("<Q", b)[0] if len(b) == 8 else 0

    def u32(self, rva: int) -> int:
        b = self.read(rva, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else 0

    def i32(self, rva: int) -> int:
        b = self.read(rva, 4)
        return struct.unpack("<i", b)[0] if len(b) == 4 else 0

    def f32(self, rva: int, count: int = 1) -> tuple[float, ...] | None:
        b = self.read(rva, 4 * count)
        return struct.unpack("<%df" % count, b) if len(b) == 4 * count else None

    def cstr(self, rva: int, limit: int = 200) -> str | None:
        """读 RVA 处的 C 字符串；必须是可打印 ASCII 才返回，否则 None。"""
        if not (0 <= rva < self.size_of_image - 1):
            return None
        raw = self.read(rva, min(limit, self.size_of_image - rva))
        end = raw.find(b"\x00")
        if end <= 0:
            return None
        try:
            s = raw[:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        if not all(32 <= ord(c) < 127 for c in s):
            return None
        return s

    def ptr_cstr(self, rva: int, limit: int = 200) -> str | None:
        """该位置存的是一个指向模块内字符串的 VA 吗？是则返回那个字符串。"""
        v = self.q(rva)
        if not (self.image_base <= v < self.image_base + self.size_of_image):
            return None
        return self.cstr(v - self.image_base, limit)

    # ---------------------------------------------------------------- 地址换算
    def to_va(self, rva: int) -> int:
        return self.image_base + rva

    def to_rva(self, va: int) -> int | None:
        off = va - self.image_base
        return off if 0 <= off < self.size_of_image else None

    def is_code_ptr(self, v: int) -> bool:
        r = self.to_rva(v)
        if r is None:
            return False
        s = self.section_of(r)
        return bool(s and s.name == ".text")

    # ---------------------------------------------------------------- 字符串
    def iter_cstrings(self, min_len: int = 2, max_len: int = 120):
        """线性扫所有 '\\x00XXXX\\x00' 段，只保留标识符形状的。

        yield (rva, text)。比正则快，也不吃内存。
        """
        buf = self._buf
        ident = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
        pos = 0
        n = len(buf)
        while True:
            pos = buf.find(b"\x00", pos)
            if pos < 0:
                return
            start = pos + 1
            end = buf.find(b"\x00", start)
            if end < 0:
                return
            ln = end - start
            if min_len <= ln <= max_len:
                seg = buf[start:end]
                if all(c in ident for c in seg):
                    yield start, seg.decode("ascii")
            pos = start

    def find_bytes(self, needle: bytes, lo: int = 0, hi: int | None = None):
        hi = self.size_of_image if hi is None else hi
        buf = self._buf
        pos = lo
        while True:
            pos = buf.find(needle, pos, hi)
            if pos < 0:
                return
            yield pos
            pos += 1

    def find_ptr_refs(self, rva: int, lo: int, hi: int, aligned: int = 8):
        """哪些位置（8 字节对齐）存着指向 rva 的绝对 VA。"""
        pat = struct.pack("<Q", self.to_va(rva))
        for p in self.find_bytes(pat, lo, hi):
            if aligned <= 1 or p % aligned == 0:
                yield p
