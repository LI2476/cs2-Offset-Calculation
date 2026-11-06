"""字节签名：让程序在**游戏更新后、不用开游戏**也能算出偏移。

## 思路

游戏更新后，`.data` 里的地址全变了、代码位置也挪了，但**访问这几个全局的
那几行指令**形状几乎不变。实测本机 client.dll：

    dwViewAngles 的访问器（0xc15987）：
        48 63 c1           movsxd rax, ecx
        48 8d 0c 40        lea    rcx, [rax+rax]      ; *2
        48 8d 05 <disp32>  lea    rax, [rip+G]        ; ← 目标
        48 8d 04 88        lea    rax, [rax+rcx*4]    ; 合计 *8
        c3                 ret

    dwViewMatrix 的访问器之一（0xc15a23）：
        48 63 c1           movsxd rax, ecx
        48 8d 0d <disp32>  lea    rcx, [rip+M]        ; ← 目标
        48 c1 e1 06        shl    rcx, 6              ; *0x40

所以做法是：**从已解出的真值处，自动截取一条签名** ——
把 disp32 抹成通配符，前后保留足够字节。新版本扫到这条签名，
读出 disp32 再算 `指令末 + disp32`，就得到新偏移。

## 为什么不用短模式

`48 8b 05 ?? ?? ?? ??` 这种 3 字节操作码在 2797 万字节里会命中十几万次。
必须带上前后的特征字节（movsxd / lea 组合、shl 常量）才有区分度。
实测本模块截出的签名在本版本里命中 1~2 次（两次是同一条指令的两个
起点，因为扫描按字节滑动），解析出的目标相同。
"""
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass, field

WILD = None


@dataclass
class Sig:
    """一条签名。

    pattern : list[int|None]，None 表示通配（disp32 的 4 个字节）
    disp_at : pattern 内 disp32 的起始下标
    expect  : 已知此版本解出的目标 RVA（只用于自检，不是答案来源）
    hits    : 上次扫描命中数
    """
    key: str
    pattern: list
    disp_at: int
    expect: int | None = None
    hits: int = 0

    def render(self) -> str:
        return "".join("??" if b is WILD else "%02x" % b for b in self.pattern)

    @staticmethod
    def parse(text: str, key: str, disp_at: int,
              expect: int | None = None) -> "Sig":
        pat = [WILD if text[i:i + 2] == "??" else int(text[i:i + 2], 16)
               for i in range(0, len(text), 2)]
        return Sig(key=key, pattern=pat, disp_at=disp_at, expect=expect)

    def find_all(self, code: bytes, limit: int = 500) -> list[int]:
        """全部匹配起点（code 内偏移）。用第一个非通配字节做粗筛。"""
        pat = self.pattern
        n = len(pat)
        anchor = next((i for i, b in enumerate(pat) if b is not WILD), 0)
        av = pat[anchor]
        out: list[int] = []
        start = 0
        while len(out) < limit:
            p = code.find(bytes([av]), start)
            if p < 0:
                break
            start = p + 1
            q = p - anchor
            if q < 0 or q + n > len(code):
                continue
            if all(b is WILD or code[q + i] == b for i, b in enumerate(pat)):
                out.append(q)
        return out

    def resolve(self, code: bytes, at: int, text_va: int) -> int:
        """把匹配点处的 disp32 换成目标 VA。

        x86-64 的 [rip+disp32] 相对**下一条指令**寻址，disp32 是 4 字节：
            目标 VA = text_va + (at + disp_at + 4) + disp32
        """
        dp = at + self.disp_at
        disp = struct.unpack_from("<i", code, dp)[0]
        return text_va + dp + 4 + disp


@dataclass
class SigSet:
    version: str = ""
    sigs: list[Sig] = field(default_factory=list)
    # 平票时的结构不变量：{键: {"index": 块内第几格, "span": 块有几格, "gap": 最大间隔}}
    # 见 solve() 里"平票"一节的说明。
    hints: dict = field(default_factory=dict)
    # 加载时版本指纹不符的原因（空串表示没问题）。见 load()。
    mismatch: str = ""

    # ------------------------------------------------------------ 结构提示
    @staticmethod
    def learn_hint(key: str, target_rva: int,
                   candidates: list[int], gap_max: int = 0x20) -> dict:
        """在一次**联机定案**之后，记住"真身在一族候选里的第几格"。

        实测 dwViewAngles 的 5 个候选是这样排的（间隔全是 0x10）：
            0x256F178 0x256F188 0x256F198 0x256F1A8 0x256F1B8
                        ↑ 真身，下标 1
        它们是同一张"角度/矩阵访问器表"的连续槽位，编译器按固定顺序摆。
        版本更新后整块都会搬走，但**槽内的相对顺序不变** ——
        这是布局常量，比票数稳。

        **踩过的坑**：第一版拿全部候选算最大间隔，一并要求 <= gap_max。
        实测候选里混着 0x2257380 这种远房噪音，最大间隔直接爆表，
        提示永远记不上（sigs.json 里 hints 是空的）。
        修法：**以真身为轴，只向两侧吸收"间隔 <= gap_max"的邻居**，
        噪音挡在族外。族至少 2 格才有意义。
        """
        c = sorted(set(candidates))
        if target_rva not in c or len(c) < 2:
            return {}
        i = c.index(target_rva)
        lo = i
        while lo > 0 and c[lo] - c[lo - 1] <= gap_max:
            lo -= 1
        hi = i
        while hi + 1 < len(c) and c[hi + 1] - c[hi] <= gap_max:
            hi += 1
        family = c[lo:hi + 1]
        if len(family) < 2:
            return {}
        gaps = [b - a for a, b in zip(family, family[1:])]
        return {"index": family.index(target_rva), "span": len(family),
                "gap": max(gaps), "base_hint": family[0]}

    @staticmethod
    def apply_hint(hint: dict, candidates: list[int],
                   gap_max: int = 0x20) -> int | None:
        """用记住的相对下标去认新版本里的真身。

        在候选里找一段**与记录时同样间隔、同样格数**的等距簇，
        取簇内第 index 个。找不到就返回 None（退回联机定案）。

        要求间隔精确相等而不是"<=：间隔值本身就是编译器排布的特征
        （角度族 0x10），放宽会把别的族误认成它。
        """
        if not hint:
            return None
        c = sorted(set(candidates))
        span, gap, idx = hint["span"], hint["gap"], hint["index"]
        if len(c) < span:
            return None
        for s in range(len(c) - span + 1):
            fam = c[s:s + span]
            if all(b - a == gap for a, b in zip(fam, fam[1:])):
                return fam[idx] if 0 <= idx < span else None
        return None

    # ------------------------------------------------------------ 截取
    @classmethod
    def extract(cls, img, xrefs, targets: dict[str, int],
                before: int = 8, after: int = 7, per_target: int = 6,
                version: str = "") -> "SigSet":
        """从已定位的真值处自动截取签名。

        **每个真值截多条**（每个引用点一条），不是只截一条。
        这是关键：单个访问器的指令形状在引擎里会被复用 ——
        实测 `cc 48 63 c1 48 8d 0c 40 48 8d 05 ????????` 在本版本命中 5 次，
        分别指向 5 个不同的全局。只要一条签名就必然选错。
        多条签名各自命中一批候选，取**被最多签名共同指向**的那个 ——
        真身的每个访问器都指向它，噪音的命中是随机散布的。

        before/after 是实测调出来的：before=8 覆盖 `movsxd + lea` 开头，
        after=7 覆盖 `shl rcx,6` / `lea rax,[rax+rcx*4]` 这类步长特征。
        """
        text_va = img.image_base + xrefs.text_rva
        code = xrefs.code
        out = cls(version=version)
        for key, rva in targets.items():
            cands = xrefs.accessor_thunks(rva, window=0x30)
            if not cands:
                continue
            cands.sort(key=lambda t: (not t["indexed"], t["stride"] is None))
            seen_pat: set[str] = set()
            for c in cands[:per_target]:
                ins = c["ins_rva"]
                o = ins - xrefs.text_rva             # code 内偏移
                disp_at = _disp_offset(code, o, text_va,
                                       img.image_base + rva,
                                       prefer=c.get("stride"))
                if disp_at is None:
                    continue
                lo = max(0, o - before)
                hi = min(len(code), o + after)
                pat = [WILD if disp_at <= (lo + i) < disp_at + 4
                       else code[lo + i] for i in range(hi - lo)]
                sig = Sig(key=key, pattern=pat, disp_at=disp_at - lo,
                          expect=rva)
                txt = sig.render()
                if txt in seen_pat:
                    continue
                seen_pat.add(txt)
                out.sigs.append(sig)
        return out

    # ------------------------------------------------------------ 扫描
    def solve(self, img, verbose: bool = True) -> dict[str, dict]:
        """在新 DLL 上扫签名，返回 {全局名: {rva, hits, votes, ...}}。

        投票规则：
          * 一条签名命中多个地址时，每个命中都算一票（不取第一个）；
          * 目标必须落在可写数据段（.data/.bss），否则丢弃 ——
            实测错命中的 0x1bad460 落在 .text 里，这一刀就砍掉了；
          * **相邻命中合并**：按字节滑动扫描会把同一条指令命中两次
            （起点差 1），必须聚成一组只算 1 票，否则假目标会被重复计票。

        ## 平票怎么打破

        实测 dwViewAngles 有 5 个候选各得 1~2 票：
            0x256F178 / 0x256F188 / 0x256F198 / 0x256F1A8 / 0x256F1B8
        它们是**同一族 thunk**，代码形状几乎逐字节相同（只差 disp32），
        所以签名的票数天然相同，靠签名本身**无法**分出真身。

        **踩过的坑**：试过"离视图矩阵的访问器最近者胜"。结果恰恰相反 ——
        真身 0x256F188 的访问器在 0xc15987，离矩阵访问器 0xc15a23 有 0x9c；
        而假货 0x256F1B8 的访问器在 0xc15a07，只差 0x1c，离得**最近**。
        越近越像，是因为编译器把同族 thunk 排在一起，跟真值无关。

        也试过"元素步长必须符合预期"（matrix 0x40 / angles 0x8）——
        在修好 thunk 的 ret 边界之后，这 5 个的步长**全是 0x8**，
        步长也不能区分（真正步长 0x40 的是矩阵的另一个 thunk 0xc15a23）。

        结论：签名只负责**把 2797 万字节缩到 5 个候选**，不负责定案。
        定案交给动态语义门（读活进程内存验值），见 auto.sig_resolve。
        本函数因此按"票数 → 地址"排序返回**完整候选表**，供上层逐个验。

        唯一的例外是 `hints`：如果上一次联机定案时记下了"真身是族里第几格"，
        且这次候选仍是一族等距槽位、数量也没变，就直接按位置认。
        这是布局常量，见 learn_hint 的注释。
        """
        text = next(s for s in img.sections if s.name == ".text")
        code = img.read(text.va, text.vsize) or b""
        text_va = img.image_base + text.va
        data_secs = [(s.va, s.va + max(s.vsize, 0x1000))
                     for s in img.sections if s.name in (".data", ".bss")]
        res: dict[str, dict] = {}
        for sig in self.sigs:
            hits = sig.find_all(code)
            sig.hits = len(hits)
            # 相邻命中（差 <= 2 字节）聚成一组，一组算 1 票
            groups: list[list[int]] = []
            for h in sorted(hits):
                if groups and h - groups[-1][-1] <= 2:
                    groups[-1].append(h)
                else:
                    groups.append([h])
            votes: dict[int, int] = {}
            for g in groups:
                h = g[0]
                rva = sig.resolve(code, h, text_va) - img.image_base
                if not (0 <= rva < img.size_of_image):
                    continue
                if not any(a <= rva < b for a, b in data_secs):
                    continue                    # 不在数据段 → 噪音
                votes[rva] = votes.get(rva, 0) + 1
            slot = res.setdefault(sig.key, {"votes": {}, "sigs": 0})
            slot["sigs"] += 1
            for rva, n in votes.items():
                slot["votes"][rva] = slot["votes"].get(rva, 0) + n

        for key, slot in res.items():
            v = sorted(slot["votes"].items(), key=lambda kv: (-kv[1], kv[0]))
            expect = next((s.expect for s in self.sigs if s.key == key), None)
            # rva 只是"票数最高者"，不保证是真身 —— 上层必须用动态门复核。
            slot["rva"] = v[0][0] if v else None
            slot["best_votes"] = v[0][1] if v else 0
            slot["candidates"] = [rva for rva, _ in v]
            slot["n_candidates"] = len(v)
            slot["top"] = v[:5]

            # 结构提示优先于票数（见 learn_hint 的注释）
            hint = self.hints.get(key)
            if hint and len(v) > 1:
                got = self.apply_hint(hint, slot["candidates"])
                if got is not None:
                    slot["by_hint"] = {"from": slot["rva"], "to": got,
                                       "index": hint["index"],
                                       "span": hint["span"]}
                    slot["rva"] = got

            slot["confident"] = (len(v) == 1) or ("by_hint" in slot)
            if verbose:
                tag = ""
                if expect is not None and v:
                    tag = "  ✓" if slot["rva"] == expect else \
                          "  ✗ 本版解出 %#x" % expect
                how = "（按签名族第 %d 格认）" % slot["by_hint"]["index"] \
                    if "by_hint" in slot else ""
                print("  %-26s %d 条签名 → 票数 %-2d，候选 %-2d 个%s%s"
                      % (key, slot["sigs"], slot["best_votes"], len(v), tag, how))
        return res

    # ------------------------------------------------------------ 存取
    def fingerprint(self, img) -> dict:
        """版本指纹：不靠人写的版本串，直接取 DLL 里改不掉的三个量。

        **踩过的坑**（2026-11-06 游戏更新时踩的，和 xref 缓存同一个坑）：
        `version` 是 `"%08x" % img.timestamp`，而 `load()` 从来**没有比对**过它。
        游戏更新后 .text 变长、所有引用位置错位，旧签名照样被拿来扫新 DLL，
        结果是"票数满、候选一堆、全是错的" —— 比报错更危险。
        所以存盘时把 `size_of_image` / `.text` 长度 / `timestamp` 一起写进去，
        加载时逐项比对，任一不符就当没有签名库（宁可让用户重跑联机）。
        """
        text = next((s for s in img.sections if s.name == ".text"), None)
        return {"fp_size_of_image": img.size_of_image,
                "fp_text_vsize": text.vsize if text else 0,
                "fp_timestamp": getattr(img, "timestamp", 0) or 0}

    def dump(self, img=None) -> dict:
        d = {"version": self.version,
             "sigs": [{"key": s.key, "pattern": s.render(),
                       "disp_at": s.disp_at, "expect": s.expect}
                      for s in self.sigs],
             "hints": self.hints}
        if img is not None:
            d.update(self.fingerprint(img))
        return d

    def save(self, path: str, img=None) -> None:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.dump(img), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str, img=None, verbose: bool = False) -> "SigSet":
        """读签名库。传了 img 就顺带校验版本指纹，不符返回带 `mismatch` 的空库。

        **返回 None 会炸上层**（solve_offline 直接 .solve），所以版本不符时返回
        一个 `sigs` 为空的 SigSet，并把原因塞进 `.mismatch` —— 上层据此报
        "签名库来自旧版本，请重跑联机"，而不是拿错位的签名硬扫出假答案。
        """
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        self = cls(version=d.get("version", ""),
                   hints=d.get("hints", {}) or {})
        for s in d["sigs"]:
            self.sigs.append(Sig.parse(s["pattern"], s["key"], s["disp_at"],
                                       s.get("expect")))
        self.mismatch = ""
        if img is not None:
            want = self.fingerprint(img)
            for k, v in want.items():
                have = d.get(k)
                if have is None:
                    self.mismatch = ("签名库无版本指纹（旧格式），无法确认适用于 "
                                     "SizeOfImage=%#x" % v)
                    break
                if int(have) != int(v):
                    self.mismatch = ("签名库版本不符：%s 记录 %#x，当前 %#x"
                                     % (k[3:], int(have), int(v)))
                    break
            if self.mismatch:
                self.sigs = []
                self.hints = {}
                if verbose:
                    print("  ! %s —— 按无签名库处理，请重跑联机生成" % self.mismatch)
        return self


def _disp_offset(code: bytes, ins: int, text_va: int,
                 target_va: int, prefer: int | None = None) -> int | None:
    """在指令起点后 2..12 字节内找出指向 target 的 disp32 位置（code 内绝对偏移）。

    不做完整反汇编 —— 逐个位置按 RIP 相对算一遍，命中即命中。
    一条 lea 的 disp32 不会出现在前 2 字节（那是 REX + opcode），所以从 2 开始。

    **踩过的坑**：这里 `ins` 是 code 内偏移，`text_va` 是段首 VA。
    第一版传了 `text_va + ins` 进来，函数里又加了一次 `ins`，
    RIP 被算成 `2*ins + ...`，于是永远命中不了，签名一条都截不出来。

    `prefer` 是 accessor 推断出的步长。同一条指令里可能有两个 disp32
    都"算得上"（一个是真目标，一个是跳转表之类），用步长特征排前面。
    """
    found = []
    for d in range(2, 13):
        p = ins + d
        if p + 4 > len(code):
            break
        disp = struct.unpack_from("<i", code, p)[0]
        if text_va + p + 4 + disp == target_va:
            found.append(p)
    return found[0] if found else None
