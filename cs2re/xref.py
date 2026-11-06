"""静态交叉引用引擎：找"哪条指令引用了哪个全局变量"。

为什么必须要有它：CS2 引擎每帧把同一份 (pitch, yaw) 复制到 .data 里十几处，
**动态采样永远分不出谁是真身**（实测 7 个候选在 25 次采样里误差全部 0.000）。
唯一有区分度的是静态结构：真身被"相机更新代码"按槽位索引访问，
副本只是被 memcpy 搬过去，甚至**一次都不被代码直接引用**。

本模块做三件事：
  1. 扫 .text，把所有 `[rip+disp32]` 形式的引用建成索引（两种方向：按目标 / 按指令）；
  2. 检测"按索引取元素"的访问器 thunk，推断元素步长；
  3. 给一个关键地址，列出"和它出现在同一函数里的其他全局"。

**踩过的坑（务必保留）**：段表里的 `section.va` 是 RVA，不是 VA。
拿它去和 `image_base + rva` 比较会永远差一个装载基址，结果恒为 0 个引用。
第一版就这么写的，白跑了一轮。

**坑二**：`self.code` 从 .text 段首（RVA 0x1000）开始，所以数组下标 p
必须加 text_rva 才是真实指令 RVA。第一版漏了这个加法，报出来的引用地址
整体少 0x1000（报 0xc14987，真实 0xc15987）。
"""
from __future__ import annotations

import os
import struct
from collections import defaultdict

import numpy as np

# ---------------------------------------------------------------- 指令模式表
# 只收 "ModRM.mod=00, rm=101" 的形式 —— 这是 x86-64 里唯一的 RIP 相对寻址，
# 且不带 SIB。带 SIB 的 (rm=100) 是 [base+index*scale]，不涉及 RIP。
REX = (0x48, 0x4C, 0x49, 0x4D, 0x44, 0x40, 0x41, 0x4B, 0x4F, 0x45)
# 单字节 opcode（后面跟 ModRM），都是会碰内存的常见指令
OPS1 = (0x8B, 0x89, 0x8D, 0x03, 0x2B, 0x39, 0x85, 0x01, 0x29, 0x31,
        0x3B, 0x0B, 0x23, 0x33, 0x87, 0xFF, 0xC7, 0x63, 0x0F)
# 两字节 opcode（0F XX），SSE 的 load/store/算术几乎全在这里
OPS2 = (0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x28, 0x29,
        0x2E, 0x2F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5C, 0x5D, 0x5E, 0x5F, 0x6E, 0x6F, 0x7E,
        0x7F, 0xD6, 0x2A, 0x2B, 0x2C, 0x2D)
LEGACY_PREFIX = (b"", b"\x66", b"\xf3", b"\xf2")


def _build_patterns() -> list[tuple[bytes, int]]:
    """返回 [(字节模式, disp32 在模式内的偏移)]，长模式优先。"""
    out: list[tuple[bytes, int]] = []
    for rex in REX:
        for op in OPS1:
            for reg in range(8):
                modrm = (reg << 3) | 0x05
                out.append((bytes([rex, op, modrm]), 3))
    for op in OPS1:
        for reg in range(8):
            out.append((bytes([op, (reg << 3) | 0x05]), 2))
    for pre in LEGACY_PREFIX:
        for op in OPS2:
            for rex in (b"", b"\x44", b"\x4c"):
                for reg in range(8):
                    modrm = (reg << 3) | 0x05
                    pat = pre + b"\x0f" + bytes([op]) + rex + bytes([modrm])
                    out.append((pat, len(pre) + 4))
                    pat2 = pre + rex + b"\x0f" + bytes([op, modrm])
                    out.append((pat2, len(pre) + 4))
    seen: dict[bytes, int] = {}
    for pat, off in out:
        seen.setdefault(pat, off)
    return sorted(seen.items(), key=lambda kv: -len(kv[0]))


PATTERNS = _build_patterns()
CACHE_VERSION = 3          # 改了扫描逻辑就 +1，旧缓存自动失效


class Xrefs:
    """一次性扫完 .text，之后按目标地址查询。

    内部用两条 NumPy 数组索引，比 dict 省内存也快：
      *_by_target —— 按目标 VA 排序，(targets, counts, offs)
      *_by_ins    —— 按指令偏移排序，(ins, targets)
    """

    def __init__(self, img, verbose: bool = False):
        self.img = img
        text = next(s for s in img.sections if s.name == ".text")
        self.text_rva = text.va                      # ← RVA，不是 VA
        self.text_va = img.image_base + text.va
        code = img.read(text.va, text.vsize) or b""
        self.code = code
        # 目标可落在这几个段里（引用只有落在已定义段才有意义）
        self.target_ranges = [(img.image_base + s.va,
                               img.image_base + s.va + max(s.vsize, 0x1000))
                              for s in img.sections if s.vsize > 0]
        self._scan(verbose)

    # ------------------------------------------------------------ 扫描
    def _scan(self, verbose: bool) -> None:
        code = self.code
        lo = self.text_va
        ranges = self.target_ranges
        pairs: list[tuple[int, int]] = []           # (target_va, ins_rva)
        for pat, doff in PATTERNS:
            start = 0
            while True:
                p = code.find(pat, start)
                if p < 0:
                    break
                start = p + 1
                dp = p + doff
                if dp + 4 > len(code):
                    continue
                disp = struct.unpack_from("<i", code, dp)[0]
                target = lo + dp + 4 + disp
                for a, b in ranges:
                    if a <= target < b:
                        pairs.append((target, p + self.text_rva))
                        break
        if not pairs:
            raise RuntimeError("xref 扫描结果为空 —— PE 读取或段表有问题")
        arr = np.array(pairs, dtype=np.int64)

        # 按目标排
        order = np.argsort(arr[:, 0], kind="stable")
        byt = arr[order]
        self.targets, counts = np.unique(byt[:, 0], return_counts=True)
        self.counts = counts.astype(np.int32)
        self.offs = byt[:, 1].astype(np.int64)
        self.starts = np.concatenate(([0], np.cumsum(self.counts)[:-1])) \
            if self.counts.size else np.zeros(0, np.int64)

        # 按指令排（供 neighbors 用）
        order2 = np.argsort(arr[:, 1], kind="stable")
        byi = arr[order2]
        self.ins_offs = byi[:, 1].astype(np.int64)
        self.ins_targets = byi[:, 0].astype(np.int64)

        if verbose:
            print("  xref: %d 条引用，覆盖 %d 个不同目标（.text %d 字节）"
                  % (len(arr), int(self.targets.size), len(code)))

    # ------------------------------------------------------------ 缓存
    def _fingerprint(self) -> dict:
        """这份缓存属于哪个 DLL —— 换版本就必须作废。

        只比 `.text` 起始地址是不够的：实测一次游戏更新里 `.text` 起点
        仍然是 0x1000，但长度从 0x1AAF2E0 变了，整段代码整体位移，
        所有引用位置全部错位。起点相同就等于"命中缓存"，会拿旧偏移去
        查新 DLL，结果全错而且不报错 —— 这是最危险的一类失败。

        所以三样一起记：模块总大小、.text 长度、PE 时间戳。
        任何一个对不上，就让调用方重建索引。
        """
        text = next(s for s in self.img.sections if s.name == ".text")
        return {
            "fp_size_of_image": np.int64(self.img.size_of_image),
            "fp_text_vsize": np.int64(text.vsize),
            "fp_timestamp": np.int64(getattr(self.img, "timestamp", 0) or 0),
        }

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        np.savez_compressed(
            path, version=np.int64(CACHE_VERSION),
            text_rva=np.int64(self.text_rva), text_va=np.int64(self.text_va),
            targets=self.targets, counts=self.counts, offs=self.offs,
            starts=self.starts,
            ins_offs=self.ins_offs, ins_targets=self.ins_targets,
            **self._fingerprint(),
        )

    @classmethod
    def load(cls, path: str, img, verbose: bool = False) -> "Xrefs | None":
        if not os.path.exists(path):
            return None
        try:
            z = np.load(path)
            if int(z["version"]) != CACHE_VERSION:
                return None
            self = cls.__new__(cls)
            self.img = img
            self.text_rva = int(z["text_rva"])
            self.text_va = int(z["text_va"])
            text = next(s for s in img.sections if s.name == ".text")
            if text.va != self.text_rva:
                return None                        # 换了版本，缓存不适用
            # 起点相同不算数 —— 必须三样指纹全对上（见 _fingerprint 的注释）。
            # 旧格式缓存没有这三项，直接判失效，让它重建一次。
            try:
                if int(z["fp_size_of_image"]) != img.size_of_image:
                    if verbose:
                        print("  xref: 缓存版本不符（模块大小变了），重建索引")
                    return None
                if int(z["fp_text_vsize"]) != text.vsize:
                    if verbose:
                        print("  xref: 缓存版本不符（.text 长度 %#x → %#x），重建索引"
                              % (int(z["fp_text_vsize"]), text.vsize))
                    return None
                if int(z["fp_timestamp"]) != (getattr(img, "timestamp", 0) or 0):
                    if verbose:
                        print("  xref: 缓存版本不符（时间戳变了），重建索引")
                    return None
            except KeyError:
                if verbose:
                    print("  xref: 缓存无版本指纹（旧格式），重建索引")
                return None
            self.code = img.read(text.va, text.vsize) or b""
            self.targets = z["targets"]
            self.counts = z["counts"]
            self.offs = z["offs"]
            self.starts = z["starts"]
            self.ins_offs = z["ins_offs"]
            self.ins_targets = z["ins_targets"]
            if verbose:
                print("  xref: 命中缓存（%d 条引用 / %d 个目标）"
                      % (len(self.offs), int(self.targets.size)))
            return self
        except Exception:
            return None

    # ------------------------------------------------------------ 查询
    def rva(self, target_rva: int) -> list[int]:
        """引用该 RVA 的**指令真实 RVA** 列表。"""
        va = self.img.image_base + target_rva
        i = int(np.searchsorted(self.targets, va))
        if i >= self.targets.size or int(self.targets[i]) != va:
            return []
        s, n = int(self.starts[i]), int(self.counts[i])
        return [int(v) for v in self.offs[s:s + n]]

    def ref_count(self, target_rva: int) -> int:
        va = self.img.image_base + target_rva
        i = int(np.searchsorted(self.targets, va))
        if i >= self.targets.size or int(self.targets[i]) != va:
            return 0
        return int(self.counts[i])

    def accessor_thunks(self, target_rva: int, window: int = 0x30) -> list[dict]:
        """识别"按索引取元素"的访问器，返回步长推断结果。

        实测形态（本机 2026-11-04，client.dll）：
            0x256F188（视角数组，步长 8）：
                48 63 c1        movsxd rax, ecx     ; 索引
                48 8d 0c 40     lea    rcx, [rax+rax]   ; *2
                48 8d 05 ..     lea    rax, [rip+G]
                48 8d 04 88     lea    rax, [rax+rcx*4] ; 合计 *8
                c3              ret
            0x256F250（视图矩阵，步长 0x40）：
                48 63 c1        movsxd rax, ecx
                48 8d 0c 40     lea    rcx, [rax+rax]
                48 8d 0d ..     lea    rcx, [rip+MATRIX]
                48 c1 e0 06     shl    rax, 6           ; *0x40
                48 03 c1        add    rax, rcx
                c3              ret

        判据：引用点前 0x20 字节内有 `movsxd rax, ecx`（按 int 索引），
        后 window 字节内出现 shl/lea 缩放。
        """
        out = []
        for ins_rva in self.rva(target_rva):
            raw_lo = max(self.text_rva, ins_rva - 0x20) - self.text_rva
            # **向后也要在 ret 处截断**：窗口左边界常常落进前一个 thunk 的
            # 尾巴，如果不砍掉，前一个 thunk 的 `48 8d 0c 40` 会被当成本
            # thunk 的"*2"，进而误算出步长。
            back = self.code[raw_lo:ins_rva - self.text_rva]
            cutb = back.rfind(b"\xc3")
            if cutb >= 0:
                back = back[cutb + 1:]
            fwd = self.code[ins_rva - self.text_rva:
                            ins_rva - self.text_rva + window]
            # **向前必须在 ret 处截断**：否则窗口会伸进紧邻的下一个 thunk，
            # 把它的 `shl rcx, 6` 当成自己的步长。实测 0x256F1B8 的访问器
            # （0xc15a07）就是这样被误判成步长 0x40 的 —— 真正的 matrix
            # 访问器在 0xc15a23，只差 0x1c 字节。
            cutf = fwd.find(b"\xc3")
            if cutf >= 0:
                fwd = fwd[:cutf]
            body = back + fwd
            if not body:
                continue
            idx_by_ecx = b"\x48\x63\xc1" in body or b"\x63\xc1" in body
            stride = None
            # shl reg, imm8 : C1 /4 ib  （(modrm>>3)&7 == 4）
            for i in range(len(body) - 3):
                if body[i] == 0xC1 and (body[i + 1] & 0x38) == 0x20:
                    stride = 1 << body[i + 2]
                    break
            # lea reg,[base+index*scale]，且前面有 lea reg,[reg+reg]（*2）
            if stride is None:
                dbl = body.find(b"\x48\x8d\x0c\x40")
                if dbl >= 0:
                    after = body[dbl + 4:]
                    for i in range(len(after) - 3):
                        if after[i] == 0x48 and after[i + 1] == 0x8D and \
                                after[i + 2] in (0x04, 0x0C, 0x14, 0x1C):
                            sib = after[i + 3]
                            stride = 2 * (1 << ((sib >> 6) & 3))
                            break
            out.append({"ins_rva": ins_rva, "indexed": idx_by_ecx,
                        "stride": stride})
        return out

    def thunk_containing(self, rva: int) -> tuple[int, int] | None:
        """若 rva 是某条函数的入口，返回该函数的 [start_rva, end_rva)。

        判据：从 rva 往后到第一个 c3（ret）为止，整段里不含 cc（int3 填充）。
        cc 是编译器在函数之间插的对齐填充，所以"到 ret 都不含 cc"
        就等于"这段确实是一条完整函数"。
        若 rva 前一个字节是 cc 或 0x00，更稳（说明它是函数开头）。
        """
        o = rva - self.text_rva
        if o < 0 or o >= len(self.code):
            return None
        prev = self.code[o - 1] if o > 0 else 0xCC
        end = self.code.find(b"\xc3", o)
        if end < 0 or end - o > 0x400:
            return None
        seg = self.code[o:end]
        if b"\xcc" in seg:
            return None
        # 前后都是填充 → 确认是独立函数
        tail = self.code[end + 1:end + 6]
        if prev not in (0xCC, 0x00) and not tail.startswith(b"\xcc"):
            return None
        return (rva, rva + (end - o) + 1)

    def best_accessor(self, target_rva: int) -> dict | None:
        """挑一个最有说服力的访问器：优先 indexed 且有步长。"""
        cands = self.accessor_thunks(target_rva)
        if not cands:
            return None
        cands.sort(key=lambda t: (not t["indexed"], t["stride"] is None))
        return cands[0]

    def co_located(self, a_rva: int, b_rva: int, window: int = 0x1000,
                   limit: int = 8) -> list[tuple[int, int, int]]:
        """列出 A 与 B 的引用点里、彼此距离 <= window 的配对。

        同一函数内引用两个不同全局变量 → 这段代码在处理它们的关系
        （例如"读矩阵、读视角角、算相机朝向"）。
        这是把十几个数值完全相同的候选收敛到 1 个的关键判据。
        """
        ra, rb = self.rva(a_rva), self.rva(b_rva)
        pairs = [(x, y, abs(x - y)) for x in ra for y in rb if abs(x - y) <= window]
        pairs.sort(key=lambda t: t[2])
        return pairs[:limit]

    def min_distance(self, a_rva: int, b_rva: int) -> int | None:
        """两个全局的引用点在代码里的最小距离（字节）。无引用返回 None。"""
        ra, rb = self.rva(a_rva), self.rva(b_rva)
        if not ra or not rb:
            return None
        arr = np.array(sorted(ra), dtype=np.int64)
        best = None
        for y in rb:
            i = int(np.searchsorted(arr, y))
            for j in (i - 1, i):
                if 0 <= j < arr.size:
                    d = abs(int(arr[j]) - y)
                    if best is None or d < best:
                        best = d
        return best

    def neighbors(self, target_rva: int, window: int = 0x40) -> list[tuple[int, int]]:
        """和 target 出现在同一段指令流附近的其他全局目标：[(target_rva, 距离)]。"""
        mine = set(self.rva(target_rva))
        if not mine:
            return []
        near: dict[int, int] = {}
        for ins in mine:
            lo = int(np.searchsorted(self.ins_offs, ins - window))
            hi = int(np.searchsorted(self.ins_offs, ins + window, side="right"))
            for k in range(lo, hi):
                tgt = int(self.ins_targets[k])
                d = abs(int(self.ins_offs[k]) - ins)
                if tgt in near:
                    near[tgt] = min(near[tgt], d)
                else:
                    near[tgt] = d
        out = [(self.img.to_rva(t), d) for t, d in near.items()
               if t != self.img.image_base + target_rva]
        out.sort(key=lambda kv: kv[1])
        return out
