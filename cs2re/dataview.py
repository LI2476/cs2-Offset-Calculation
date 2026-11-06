"""把 .data 整块搬到内存再用 numpy 扫 —— 比逐槽 ReadProcessMemory 快两个数量级。

逐槽读 77 万个 8 字节，光是 ctypes 调用开销就要 4 秒起；
整块读一次 5.9MB 只要 0.05 秒，之后所有筛选都在本地数组里做。
"""
from __future__ import annotations

import time

import numpy as np

from .live import GameProcess
from .pe import Image


class DataView:
    """.data 段的活内存快照。"""

    def __init__(self, proc: GameProcess, img: Image, section: str = ".data"):
        sec = next((s for s in img.sections if s.name == section), None)
        if sec is None:
            raise LookupError("镜像里没有 %s 段" % section)
        self.name = section
        self.rva = sec.va
        self.vsize = sec.vsize
        t0 = time.time()
        raw = proc.read_chunked(sec.va, sec.vsize)
        self.raw = raw
        self.elapsed = time.time() - t0
        self.built_at = time.time()          # 快照完成时刻，用于判断"这份快照多旧了"
        self.taken_at = t0
        self.unreadable = list(getattr(proc, "unreadable", []))
        # 对齐到 8 字节的 qword 视图（段首 0x21c2000 本身是 0x1000 对齐）
        n8 = len(raw) // 8
        self.q = np.frombuffer(raw[: n8 * 8], dtype="<u8")
        n4 = len(raw) // 4
        self.i32 = np.frombuffer(raw[: n4 * 4], dtype="<i4")
        self.f32 = np.frombuffer(raw[: n4 * 4], dtype="<f4")

    # ------------------------------------------------------------ 定位
    def qword_rva(self, idx: int) -> int:
        return self.rva + idx * 8

    def rva_to_idx(self, rva: int) -> int:
        """RVA -> qword 数组下标（8 字节粒度）。"""
        return (rva - self.rva) // 8

    def rva_to_idx32(self, rva: int) -> int:
        """RVA -> dword 数组下标（4 字节粒度）。f32/i32 用这个。"""
        return (rva - self.rva) // 4

    # ------------------------------------------------------------ 筛选
    def heap_ptr_mask(self) -> np.ndarray:
        """哪些 qword 像"指向已提交内存的指针"。"""
        q = self.q
        return (q > 0x10000) & (q < 0x7FFF_FFFF_FFFF)

    def module_ptr_mask(self, img: Image) -> np.ndarray:
        """哪些 qword 指向本模块内部。"""
        lo = img.image_base
        hi = img.image_base + img.size_of_image
        return (self.q >= lo) & (self.q < hi)

    def find_pairs(self, expect: tuple[float, float]) -> np.ndarray:
        """找"连续两个 float 等于 expect"的位置，返回 rva 数组（4 字节步长）。

        用整数位模式精确比较，避开 NaN 比较和 float32 精度问题。
        """
        import struct as _s
        a = _s.unpack("<i", _s.pack("<f", np.float32(expect[0])))[0]
        b = _s.unpack("<i", _s.pack("<f", np.float32(expect[1])))[0]
        i32 = self.i32
        n = len(i32) - 1
        hit = (i32[:n] == a) & (i32[1:n + 1] == b)
        return self.rva + np.nonzero(hit)[0] * 4

    def stats(self) -> dict:
        return {
            "section": self.name,
            "rva": self.rva,
            "vsize": self.vsize,
            "read_s": round(self.elapsed, 3),
            "unreadable_pages": len(self.unreadable),
        }
