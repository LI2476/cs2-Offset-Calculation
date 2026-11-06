"""全自动偏移量扫描器 —— 一条命令从磁盘 DLL + 活进程算出所有偏移。

## 为什么要"动态 + 静态"两套证据

动态采样（内存里找符合特征的值）**永远分不出真假**，这是本项目最贵的教训：

    dwViewAngles 那一轮，.data 里有 7 个候选在同一帧的 (pitch, yaw) 与
    视图矩阵反推值**误差全部是 0.000000**，连采 25 次 25/25 全中。
    引擎每帧把同一份角度复制到十几处，副本和真身在数值上完全一样。

真正有区分度的是**静态结构**：真身被"相机更新代码"按索引访问，
副本只是被 memcpy 搬过去，甚至一次都不被代码直接引用。

**但零引用不是判决书** —— 这条教训是把前面那句写死之后又踩回来的：
实测 dwLocalPlayerPawn（0x2569948）在 2797 万字节 .text 里 RIP 引用为 0，
它却是真身 —— 指针类全局靠寄存器间接寻址，静态扫不到引用是正常的。
所以零引用只对"标量/数组类"扣分，指针类不扣。

所以每个候选都要过两道：
  1. 动态门（gates.py）：值的样子对不对（矩阵正交归一、实体表 vtable、角度自洽）；
  2. 静态门（xref.py）：有没有代码在用它、是不是按索引取元素、步长对不对、
     和已验证的锚点（视图矩阵）是不是出现在同一函数里。

## 打分

动态门给基础分（0~100），静态证据做加减，最后按总分排序取第一。
分差写进报告，**绝不允许"把基准值改成工具算出来的值"** —— 那是自欺欺人。

用法：
    python -m cs2re.auto                 # 全自动：自己找进程、自己找 DLL
    python -m cs2re.auto --no-live       # 只跑静态部分（Tier A + 引用统计）
    python -m cs2re.auto --pid 1234      # 指定进程
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import cvars, gates, live, pe
# 别写成 `report`：本模块自己有个 report(res) 函数，同名会把模块覆盖掉。
from . import report as rpt
from .dataview import DataView
from .discover_global import (Slot, demote_array_members, group_by_value,
                              scan_entity_list, scan_local_player,
                              scan_viewangles, scan_viewmatrix)
from .sig import SigSet
from .targets import TIER_B
from .xref import Xrefs

# ---------------------------------------------------------------- 默认路径
# client.dll 路径不写死：用 --dll 传，或设环境变量 CS2RE_DLL。
DEFAULT_DLL = os.environ.get("CS2RE_DLL", "")
CACHE_DIR = Path(__file__).resolve().parent.parent / "_cache"
XREF_CACHE = CACHE_DIR / "xref_client.npz"
SCHEMA_CACHE = CACHE_DIR

# .data 段范围（RVA）。实测 .data rva=0x21C2000 vsize=0x5E4C3C，
# 留点余量避免边界漏掉最后一个槽。
DATA_LO, DATA_HI = 0x21C2000, 0x27B0000

# 每个全局的"结构指纹"：用来给静态证据打分。
# stride = 该全局如果是数组，元素步长应该是多少。
EXPECT: dict[str, dict] = {
    "dwViewMatrix":            {"stride": 0x40, "kind": "matrix"},
    "dwViewAngles":            {"stride": 0x08, "kind": "vec2"},
    "dwEntityList":            {"stride": None, "kind": "ptr"},
    "dwLocalPlayerController": {"stride": None, "kind": "ptr"},
    "dwLocalPlayerPawn":       {"stride": None, "kind": "ptr"},
    # convar 类：拿"对象自报的名字"定案，不需要动态门也不需要基准。
    "dwSensitivity":           {"kind": "cvar", "cvar": "sensitivity",
                                "module": "client.dll", "expect": 0x2567C48},
    "dwGameTypes":             {"kind": "cvar", "cvar": "game_type",
                                "module": "matchmaking.dll", "expect": 0x1E2740},
}

# 静态门权重
W_NO_REF = -70       # 一次都不被引用 —— 数据副本，几乎可以判死（仅对矩阵/角度类）
W_NO_REF_PTR = 0     # 指针类零引用是正常的（见下方注释），不奖不罚
W_HAS_REF = 5        # 至少被引用一次
W_INDEXED = 12       # 被"按索引取元素"的访问器引用（真身特征）
W_STRIDE_OK = 10     # 访问器步长与预期一致
W_STRIDE_BAD = -15   # 步长明显不对
W_NEAR_ANCHOR = 18   # 与锚点（视图矩阵）出现在同一函数
W_NEAR_FAR = -5      # 引用点离锚点很远（> 0x8000）
W_DYN_OK = 25        # 动态语义门完全通过时的额外确认（用于覆盖静态门的罕见反例）
W_SLOT_ADJ = -8      # 与锚点地址"紧邻但不是它"（相邻槽陷阱）

# 动态语义门的及格线。低于此分的候选视为"语义上不是它"，
# 静态证据再多也不能让它胜出（见 score_all 的注释）。
DYN_FLOOR = 80

# 关于"指针类零引用"：实测 dwLocalPlayerPawn 0x2569948 在 2797 万字节的
# .text 里**一条 RIP 相对引用都没有**（穷举了所有可能成为 disp32 的位置）。
# 但它就是真值 —— 控制器 +0x92C 的 m_hPlayerPawn 句柄经实体表解出来，
# 与这个槽的内容完全相同（0x318eed31000）。
# 说明这类全局不是用 [rip+disp] 访问的，而是由某个拿着模块基址的寄存器
# 间接寻址（mov rax,[rbx+0x2569948]），静态扫不出来。
# 所以对指针类，"零引用"不能当罪证；它的可信度来自语义门和句柄链闭合。


@dataclass
class Verdict:
    key: str
    rva: int | None = None
    score: int = 0
    dynamic: int = 0
    static: int = 0
    notes: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    expect: int | None = None
    agree: bool | None = None
    elapsed: float = 0.0
    aliases: list[int] = field(default_factory=list)
    confident: bool = True          # 离线模式下可能为 False（只见候选，未定案）

    @property
    def addr(self) -> str:
        return ("%#x" % self.rva) if self.rva is not None else "—"


# ---------------------------------------------------------------- 工具
def data_ranges(img) -> list[tuple[int, int]]:
    """可写数据段的范围（RVA 区间）。

    **别写死 0x21C2000..0x27B0000**。实测本机 client.dll 的节表：
        .text  va=0x00001000 vsize=0x1aae9c0
        .rdata va=0x01ab0000 vsize=0x07116f2
        .data  va=0x021c2000 vsize=0x05e4c2c   ← 全局都在这
        .pdata va=0x027a7000
    一写死就会包含 .pdata 的一截、又可能漏掉 .data 尾部，更新后必然错。
    改成按节名 + 可写标志（IMAGE_SCN_MEM_WRITE=0x80000000）自动取。
    """
    out = []
    for s in img.sections:
        ch = getattr(s, "chars", 0) or 0
        if s.name in (".data", ".bss") or (ch & 0x80000000):
            out.append((s.va, s.va + max(s.vsize, 0x1000)))
    return out or [(DATA_LO, DATA_HI)]


def same_value(proc, a_rva: int, b_rva: int) -> bool:
    """两个槽的内容是否完全相同（8 字节）。指针类用它判"别名"。"""
    ra = proc.read_rva(a_rva, 8)
    rb = proc.read_rva(b_rva, 8)
    return bool(ra) and ra == rb


def find_cs2(pid: int | None = None) -> live.ProcInfo | None:
    """找 cs2 进程。给 pid 就校验，不给就自动挑第一个（见 live.pick_process）。"""
    try:
        return live.pick_process("cs2", pid)
    except LookupError:
        return None


def load_xrefs(img, verbose: bool = True) -> Xrefs:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    xr = Xrefs.load(str(XREF_CACHE), img, verbose=verbose)
    if xr is None:
        t0 = time.time()
        xr = Xrefs(img, verbose=verbose)
        xr.save(str(XREF_CACHE))
        print("  xref 建索引 %.1fs（已缓存，下次秒开）" % (time.time() - t0))
    return xr


def static_evidence(xr: Xrefs, rva: int, key: str,
                    anchor_rva: int | None = None) -> tuple[int, list[str], dict]:
    """对一个候选做静态体检，返回 (加减分, 说明, 明细)。

    key 是全局变量名（如 "dwViewMatrix"），既用作 EXPECT 查表键，
    也用来决定"零引用"该不该罚分（矩阵/角度类罚，指针类不罚）。
    """
    notes: list[str] = []
    detail: dict = {}
    bonus = 0

    n = xr.ref_count(rva)
    detail["refs"] = n
    kind = EXPECT.get(key, {}).get("kind", "ptr")
    if n == 0:
        if kind == "ptr":
            # 指针类零引用是正常现象，不算罪证（见 W_NO_REF_PTR 的注释）
            bonus += W_NO_REF_PTR
            notes.append("代码零 RIP 引用（指针类正常，靠语义门定案）")
        else:
            bonus += W_NO_REF
            notes.append("代码零引用（数据副本）")
    else:
        bonus += W_HAS_REF
        notes.append("被引用 %d 次" % n)

    acc = xr.best_accessor(rva) if n else None
    if acc:
        detail["indexed"] = acc["indexed"]
        detail["stride"] = acc["stride"]
        if acc["indexed"]:
            bonus += W_INDEXED
            notes.append("按索引访问")
        want = EXPECT.get(key, {}).get("stride")
        if want is not None and acc["stride"] is not None:
            if acc["stride"] == want:
                bonus += W_STRIDE_OK
                notes.append("步长 %#x 符合" % want)
            elif acc["stride"] % want == 0 or want % acc["stride"] == 0:
                notes.append("步长 %#x（基准是 %#x，可能量的是外层数组）"
                             % (acc["stride"], want))
            else:
                bonus += W_STRIDE_BAD
                notes.append("步长 %#x 不符（应 %#x）" % (acc["stride"], want))

    if anchor_rva is not None and n:
        d = xr.min_distance(rva, anchor_rva)
        detail["anchor_dist"] = d
        if d is not None:
            if d <= 0x400:
                bonus += W_NEAR_ANCHOR
                notes.append("与锚点同函数（距 %#x）" % d)
            elif d > 0x8000:
                bonus += W_NEAR_FAR
                notes.append("离锚点很远（%#x）" % d)

    return bonus, notes, detail


def score_all(slots: list[Slot], xr: Xrefs, key: str,
              anchor: int | None) -> list[dict]:
    """给**每一个**候选打分，不只是每组第一个。

    **踩过的坑（第一处）**：一开始按"值相同"分组后取 arr[0]（地址最小的
    那个）去打分，结果真身被它自己的副本顶掉了。实测角度那一轮 31 个候选
    的 (pitch,yaw) 完全相同，分组后 21 组，每组只留最小地址 —— 真值
    0x256F188 排在第 9 位，根本没机会被评分，最后选出来的是零引用的
    0x222bda8（分 25）。修正：全部打分，按总分排序。

    **踩过的坑（第二处）**：动态分和静态分做加法，导致"动态 95 + 静态 -70"
    和"动态 15 + 静态 0"几乎同分（25 vs 15），一个纯签名猜错的候选就能
    赢过语义完全正确的候选。修正：动态门是**必要条件**，用乘法保底 ——
    动态分低于 DYN_FLOOR 的候选，总分直接被压到动态分以下。
    实测角度那 5 个相邻槽动态分为 95/0/15/15/5，加法下可能翻车，
    乘法下 95 分那个必然第一。
    """
    out = []
    for s in slots:
        dyn = s.score
        bonus, notes, detail = static_evidence(xr, s.rva, key, anchor)
        total = dyn + bonus
        if dyn < DYN_FLOOR:
            total = min(total, dyn)          # 语义门不及格 → 不允许被静态分救活
        out.append({"rva": s.rva, "score": max(0, min(100, total)),
                    "dynamic": dyn, "static": bonus, "notes": notes,
                    "detail": detail, "group": s.group, "tags": list(s.tags)})
    out.sort(key=lambda c: (-c["score"], -c["dynamic"], -c["static"], c["rva"]))
    return out


# ---------------------------------------------------------------- 各全局
def solve_viewmatrix(proc, img, dv, xr, verbose=True) -> Verdict:
    t0 = time.time()
    v = Verdict("dwViewMatrix", expect=TIER_B["dwViewMatrix"][0])
    lo, hi = data_ranges(img)[0]
    slots = scan_viewmatrix(proc, img, lo, hi, step=8, dv=dv, verbose=verbose)
    if not slots:
        v.notes.append("动态门没有任何候选")
        v.elapsed = time.time() - t0
        return v
    slots = demote_array_members(slots)
    group_by_value(slots)          # 只标 group 号，供报告提示"同值副本"
    cands = score_all(slots, xr, "dwViewMatrix", None)
    v.candidates = cands[:10]
    top = cands[0]
    v.rva, v.score, v.static = top["rva"], top["score"], top["static"]
    v.dynamic = top["dynamic"]
    v.notes = top["notes"]
    if v.expect is not None:
        v.agree = v.rva == v.expect
    v.elapsed = time.time() - t0
    return v


def solve_viewangles(proc, img, dv, xr, anchor: int | None, verbose=True) -> Verdict:
    """解 dwViewAngles：先宽窗筛候选，再逐个**实时复核**。

    **为什么要复核**：dv 是 .data 的快照，矩阵是刚读的。玩家转视角时两者
    差好几度，于是快照里的真身连预筛都过不去 —— 实测出现过"20 个候选、
    过 80 分 0 个"的空结果。修法：快照只用来圈候选（window 放到 25 度），
    判分改用 `proc.read_rva` 现读的第二份数据，此时矩阵和角度才是同刻的。
    """
    t0 = time.time()
    v = Verdict("dwViewAngles", expect=TIER_B["dwViewAngles"][0])
    if anchor is None:
        v.notes.append("锚点（视图矩阵）未解出，无法做角度自洽门")
        v.elapsed = time.time() - t0
        return v
    raw = proc.read_rva(anchor, 64)
    if not raw:
        v.notes.append("锚点读不到")
        v.elapsed = time.time() - t0
        return v
    f = struct.unpack("<16f", raw)
    rows = [f[0:4], f[4:8], f[8:12], f[12:16]]
    expect = gates.angles_from_forward(gates.matrix_forward(rows))
    lo, hi = data_ranges(img)[0]

    # ---- 判快照新旧：拿锚点（矩阵）在快照里和实时读的值一比就知道 ----
    # 玩家转视角/走动时矩阵必变，所以"快照里的矩阵 ≠ 实时矩阵"就等于
    # "这份 .data 快照已经过期"。过期时快照里的角度值会冻结在某一刻
    # （实测一直停在 (0.61, 2.23)），按窗口预筛永远捞不到真身。
    stale = False
    if dv is not None:
        i = dv.rva_to_idx32(anchor)
        if 0 <= i < len(dv.f32) - 16:
            snap = dv.f32[i:i + 16]
            diff = max(abs(float(snap[k]) - f[k]) for k in range(16))
            stale = diff > 1e-3
            if verbose and stale:
                print("  快照已过期（锚点处与实时差 %.4g），跳过窗口预筛" % diff)

    slots = scan_viewangles(proc, img, lo, hi, expect=expect,
                            step=8, dv=dv, verbose=verbose, window=25.0,
                            stale=stale)
    # ---- 实时复核：快照只圈范围，判分用现读的数据 ----
    fresh: list[Slot] = []
    for s in slots:
        got = proc.read_rva(s.rva, 8)
        if not got:
            continue
        p, y = struct.unpack("<2f", got)
        g = gates.gate_viewangles((p, y), expect)
        if g.score >= 80:
            fresh.append(Slot(s.rva, None, g.score, g.reason, list(g.tags),
                              key=(p, y)))
    if verbose and len(fresh) != len(slots):
        print("  实时复核：%d 个快照候选中有 %d 个现读仍然吻合"
              % (len(slots), len(fresh)))
    slots = fresh
    if not slots:
        v.notes.append("动态门没有任何候选")
        v.elapsed = time.time() - t0
        return v
    slots = demote_array_members(slots)
    group_by_value(slots)

    # ---- 结构否决：vec2 槽必须"按索引取元素、步长 8" ----
    # **真实踩过的坑（2026-11-04）**：0x222a3a8 这一轮动态门拿了 95 分，
    # 而真身 0x256f188 那一刻现读没对上矩阵（80 分门槛下不来），于是
    # 0x222a3a8 被当成答案写进了 .ofs，还连累签名库一起写错。
    # 它凭什么骗过动态门？因为它是**同一份角度的副本**（数值当然对），
    # 但它的访问器不按索引、也没有 0x8 步长 —— 那不是 vec2 槽的形状。
    # 静态证据在这里比动态更硬：数值可以是副本，代码形状不能。
    # 规则：只要存在"形状对"的候选，形状错的直接不参与排序。
    shaped = []
    for s in slots:
        acc = xr.best_accessor(s.rva) if xr.ref_count(s.rva) else None
        if acc and acc["indexed"] and acc["stride"] == EXPECT["dwViewAngles"]["stride"]:
            shaped.append(s)
    if shaped:
        if verbose and len(shaped) != len(slots):
            print("  结构否决：%d 个动态候选里只有 %d 个是 vec2 槽形状（索引 + 步长 0x8）"
                  % (len(slots), len(shaped)))
        slots = shaped
    elif verbose:
        print("  注意：没有任何候选符合 vec2 槽形状，退回纯动态判分")

    cands = score_all(slots, xr, "dwViewAngles", anchor)
    v.candidates = cands[:10]
    top = cands[0]
    v.rva, v.score, v.static = top["rva"], top["score"], top["static"]
    v.dynamic = top["dynamic"]
    v.notes = top["notes"] + ["矩阵反推 pitch=%.3f yaw=%.3f" % expect]
    if v.expect is not None:
        v.agree = v.rva == v.expect
    v.elapsed = time.time() - t0
    return v


def solve_entity_list(proc, img, dv, xr, verbose=True) -> Verdict:
    t0 = time.time()
    v = Verdict("dwEntityList", expect=TIER_B["dwEntityList"][0])
    lo, hi = data_ranges(img)[0]
    slots = scan_entity_list(proc, img, lo, hi,
                             h_controller=0x14BC, h_player_pawn=0x92C,
                             dv=dv, mod_base=proc.base,
                             mod_size=img.size_of_image, verbose=verbose)
    if not slots:
        v.notes.append("动态门没有任何候选")
        v.elapsed = time.time() - t0
        return v
    group_by_value(slots)
    cands = score_all(slots, xr, "dwEntityList", None)
    v.candidates = cands[:10]
    top = cands[0]
    v.rva, v.score, v.static = top["rva"], top["score"], top["static"]
    v.dynamic = top["dynamic"]
    v.notes = top["notes"]
    # 指针类：值相同的候选是**同一对象的别名**，全都可用。
    # 实测 dwEntityList 有三个槽同指 0x3186f471000（0x23bfa10 引用 56 次、
    # 0x254fe18 引用 534 次、0x271eba8 引用 956 次），它们不是竞争关系。
    v.aliases = [c["rva"] for c in cands
                 if c["rva"] != v.rva and same_value(proc, c["rva"], v.rva)]
    if v.aliases:
        v.notes.append("同值别名 %d 个：%s（都指向同一对象，均可使用）"
                       % (len(v.aliases), ", ".join("%#x" % a for a in v.aliases)))
    if v.expect is not None:
        v.agree = v.rva == v.expect or v.expect in v.aliases
        if v.agree and v.rva != v.expect:
            v.notes.append("基准 %#x 是本答案的别名" % v.expect)
    v.elapsed = time.time() - t0
    return v


def solve_local_player(proc, img, dv, xr, es_rva: int | None, want: str,
                       verbose=True, must_be: int | None = None) -> Verdict:
    key = "dwLocalPlayerController" if want == "controller" else "dwLocalPlayerPawn"
    t0 = time.time()
    v = Verdict(key, expect=TIER_B[key][0])
    if es_rva is None:
        v.notes.append("实体表未解出，无法做双向量闭合门")
        v.elapsed = time.time() - t0
        return v
    ents, diag = gates.read_entities(proc, es_rva)
    if not ents:
        v.notes.append("实体表读不到实体：%s" % "；".join(diag))
        v.elapsed = time.time() - t0
        return v
    lo, hi = data_ranges(img)[0]
    slots = scan_local_player(proc, img, lo, hi, ents,
                              h_controller=0x14BC, h_player_pawn=0x92C,
                              want=want, dv=dv, verbose=verbose,
                              must_be=must_be)
    if not slots:
        v.notes.append("动态门没有任何候选")
        v.elapsed = time.time() - t0
        return v
    group_by_value(slots)
    cands = score_all(slots, xr, key, None)
    v.candidates = cands[:10]
    top = cands[0]
    v.rva, v.score, v.static = top["rva"], top["score"], top["static"]
    v.dynamic = top["dynamic"]
    v.notes = top["notes"]
    v.aliases = [c["rva"] for c in cands
                 if c["rva"] != v.rva and same_value(proc, c["rva"], v.rva)]
    if v.aliases:
        v.notes.append("同值别名 %d 个：%s（同一对象，均可使用）"
                       % (len(v.aliases), ", ".join("%#x" % a for a in v.aliases)))
    if v.expect is not None:
        v.agree = v.rva == v.expect or v.expect in v.aliases
        if v.agree and v.rva != v.expect:
            v.notes.append("基准 %#x 是本答案的别名" % v.expect)
    v.elapsed = time.time() - t0
    return v


def solve_cvar(proc, img, key: str, verbose: bool = True) -> Verdict:
    """用"convar 对象自报名字"直接定案 —— 不需要动态门，不需要基准。

    **为什么这条最硬**：先说结论 —— 一个槽指向的对象里，`+0x00` 存的就是
    这个 convar 自己的名字（ASCII 串）。名字对上，就说明"这个槽就是那个变量"，
    没有别的解释空间。相比之下：
      * 动态门（看值像不像）会被"副本"骗 —— 引擎每帧把同一份值复制十几处；
      * 静态门（看引用次数）也会被骗 —— 早前表里有个地址被引用 56 次，
        但它指向的是模块内静态跳转表，根本不是 convar。

    实测量级：client.dll 的 .data（5.9 MB）扫完 0.8 秒，能捞出 2679 个 convar。
    所以这个办法既硬又快，代价只是"必须游戏在跑"。
    """
    t0 = time.time()
    spec = EXPECT[key]
    want = spec["cvar"]
    mod_name = spec.get("module", "client.dll")
    v = Verdict(key, expect=spec.get("expect"))

    if proc is None:
        v.notes.append("没有活进程，convar 索引无法建立")
        v.confident = False
        v.elapsed = time.time() - t0
        return v

    m = proc.module(mod_name)
    if not m:
        v.notes.append("进程里没有 %s" % mod_name)
        v.confident = False
        v.elapsed = time.time() - t0
        return v
    mbase, msize = m
    if mod_name == "client.dll":
        lo, hi = data_ranges(img)[0]
    else:
        # 非 client.dll 的模块一律扫全模块（一般只有 2 MB，很便宜）。
        # 用全模块而不是猜节表，是因为 matchmaking.dll 只有 .text/.rdata/.data
        # 三段，猜错反而漏掉 convar 所在的那一段。
        lo, hi = 0, min(msize, 0x2000000)

    idx = cvars.scan_range(cvars.Reader(proc), mbase, lo, hi)
    hit = idx.get(want)
    v.candidates = [{"rva": e["slot"], "name": nm,
                     "obj": e["obj"], "score": 100}
                    for nm, e in sorted(idx.items()) if nm == want][:1]

    if not hit:
        v.notes.append("%s 的 convar 索引里没有 %r（扫了 %d 个 convar）"
                       % (mod_name, want, len(idx)))
        v.confident = False
        v.elapsed = time.time() - t0
        return v

    r = cvars.Reader(proc)
    i, f = cvars.value(r, hit)
    desc = cvars.describe(r, hit)
    v.rva = hit["slot"]
    v.score = 100
    v.dynamic = 100
    v.static = 0
    v.notes = [
        "%s+%#x 的对象 +0x00 名字串 = %r —— 名字自证，无需其他证据"
        % (mod_name, hit["slot"], hit["name"]),
        "+0x58 当前值 int=%s float=%.4f" % (i, f or 0.0),
    ]
    if desc:
        v.notes.append("+0x20 描述 = %r" % desc[:60])
    others = [nm for nm in idx if nm != want and nm.startswith(want)]
    if others:
        v.notes.append("同类近名 %d 个（已按精确名取，不会误取）" % len(others))
    if v.expect is not None:
        v.agree = v.rva == v.expect
    v.elapsed = time.time() - t0
    return v


# ---------------------------------------------------------------- 离线（签名）
def _vote_confident(slot: dict, ratio: float = 1.5) -> bool:
    """票数是否形成压倒性优势。

    实测数据（本版本，18 条签名）：
        dwViewMatrix   6 条签名 → 投票 [6, 2, 2]       —— 6 是 2 的 3 倍
        dwLocalPlayer  6 条签名 → 投票 [6, 2, 2, 2, ...] —— 同样是 3 倍
        dwViewAngles   2 条签名 → 投票 [2, 2, 2, 2, 2]  —— 完全并列
    这里的区别不是"候选有几个"，而是**第一名是不是压倒性**。
    真身的每个访问器都指向它，噪音的命中是随机散布的 ——
    所以第一名被所有签名一致指向（票数 = 签名条数），第二名只有零星 1~2 票。
    """
    top = slot.get("top") or []
    if len(top) < 2:
        return len(top) == 1
    return top[0][1] >= max(2, ratio * top[1][1])


def solve_schema_fields(img, verbose: bool = True) -> list[Verdict]:
    """用引擎 schema 静态查出全部 m_* 字段偏移。

    **这条路不需要开游戏**：字段偏移是编译期常量，编进 client.dll 的
    类型描述表里。实测本版本 4334 个字段描述项 / 515 个类，查一遍全中。

    用 STRUCT_HINT 限定类范围是必须的 —— 字段名在引擎里重名很常见
    （m_fFlags 同时属于 C_BaseEntity@0x3f4 和另一个类@0x63），
    不给范围就只能瞎猜。

    另有三条 schema 里没有同名项（m_vecOrigin 之外的那几条复合键），
    schema.ALIASES 里明确记录，此处照抄标签输出，不编造值。
    """
    from . import schema as schema_mod
    from . import targets
    t0 = time.time()
    lo, hi = data_ranges(img)[0]
    sc = schema_mod.load_or_build_schema(img, lo, hi, SCHEMA_CACHE,
                                         verbose=verbose)
    out: list[Verdict] = []
    for k, (base, tag, desc) in targets.TIER_A.items():
        v = Verdict(k)
        v.expect = base
        hint = targets.STRUCT_HINT.get(tag, ())
        scoped = [(c, sc.offset_in(c, k)) for c in sc.classes_with(k)]
        scoped = [(c, o) for c, o in scoped if o is not None]
        pick = [x for x in scoped if targets.class_matches(x[0], hint)]
        if pick:
            v.rva = pick[0][1]
            v.notes.append("%s@%#x（%s）" % (pick[0][0], pick[0][1], desc))
            if len(pick) > 1:
                v.notes.append("同类候选 %d 个：%s"
                               % (len(pick), ", ".join(c for c, _ in pick[1:4])))
            v.confident = True
        elif scoped:
            v.rva = scoped[0][1]
            v.notes.append("%s@%#x（类标签未匹配，降级采用）"
                           % (scoped[0][0], scoped[0][1]))
            v.confident = False
        else:
            allof = sc.offsets(k)
            if allof:
                v.rva = allof[0]
                v.notes.append("%#x（无类归属，只能取首个同名项）" % allof[0])
                v.confident = False
            else:
                v.notes.append("schema 里没有这个字段名")
                v.confident = False
        v.agree = (v.rva == base) if v.rva is not None else False
        v.dynamic = 100 if v.confident else 0
        v.score = 100 if v.confident and v.agree else (60 if v.confident else 20)
        v.elapsed = 0.0
        out.append(v)
    if verbose:
        n_ok = sum(1 for v in out if v.agree)
        print("[schema] %d 个 m_* 字段全部由类型表解出，与基准一致 %d/%d，%.1fs"
              % (len(out), n_ok, len(out), time.time() - t0))
    return out


def solve_offline(img, xr, verbose: bool = True) -> dict:
    """不开游戏：仅凭 client.dll 算偏移。

    做法：读 `_cache/sigs.json`（上一次联机成功时自动存的字节签名），
    在新 DLL 的 .text 里扫这些签名，把 disp32 解回目标 RVA。

    ## 什么时候能定案，什么时候不能

    实测同一族 thunk（0x256F178 / 188 / 198 / 1A8 / 1B8）的代码形状
    逐字节相同，只差 disp32，签名扫下去票数完全一样 —— 这种情况签名本身
    分不出真身。能定案的三条路：

      1. **唯一候选**：只有一个地址被命中（dwEntityList 就是这样）。
      2. **票数压倒**：第一名被全部签名一致指向，第二名只有零星 1~2 票。
         dwViewMatrix 6:2、dwLocalPlayerController 6:2 都属于这种。
      3. **结构提示**：上次联机记下了"真身是族内第几格"，且这次的候选
         仍能拼出同样间隔、同样格数的族 → 按位置认。
         dwViewAngles 就是靠这条定案的（真身是 5 格族里的第 1 格）。

    三条都不满足时，只报候选，标注需联机确认。这是程序的诚实边界。
    """
    sig_path = str(CACHE_DIR / "sigs.json")
    if not os.path.exists(sig_path):
        print("没有签名文件 %s —— 先联机跑一次（会自动生成）" % sig_path)
        return {"ok": False, "sigs": {}, "reason": "无签名文件"}

    ss = SigSet.load(sig_path)
    print("\n[离线] 签名库版本 %s，共 %d 条签名 / %d 条结构提示"
          % (ss.version or "?", len(ss.sigs), len(ss.hints)))
    res = ss.solve(img, verbose=verbose)

    verdicts = []
    for key, slot in res.items():
        v = Verdict(key=key, rva=slot["rva"], score=0)
        n = slot["n_candidates"]
        by_hint = "by_hint" in slot
        by_vote = _vote_confident(slot)
        confident = n == 1 or by_hint or by_vote
        v.dynamic = 0
        v.static = 0
        v.score = 100 if confident else max(30, 90 - 12 * (n - 1))
        v.notes.append("%d 条签名，%d 个候选，最高票 %d"
                       % (slot["sigs"], n, slot["best_votes"]))
        if n == 1:
            v.notes.append("唯一候选 → 可直接使用")
        elif by_hint:
            h = slot["by_hint"]
            v.notes.append("按签名族位置认：%d 格族里的第 %d 格（间隔 %#x）"
                           % (h["span"], h["index"], ss.hints[key]["gap"]))
            v.notes.append("票数 %d:%d（不足以定案，靠布局常量）"
                           % (slot["top"][0][1], slot["top"][1][1]))
        elif by_vote:
            v.notes.append("票数压倒 %d:%d（真身被全部签名一致指向）"
                           % (slot["top"][0][1], slot["top"][1][1]))
        else:
            v.notes.append("多候选且票数并列，未经活进程语义门定案（置信度低）")
            v.notes.append("候选：%s" % ", ".join("%#x" % r
                                                  for r in slot["candidates"][:6]))
        v.candidates = [{"rva": r, "score": slot["votes"].get(r, 0),
                         "static": 0, "dynamic": 0, "notes": [], "detail": {},
                         "group": 0, "tags": []}
                        for r in slot["candidates"][:10]]
        v.confident = confident
        verdicts.append(v)

    # dwLocalPlayerPawn 没有代码引用，截不出签名 → 用上次联机**核实过**的钉值。
    # **踩过的坑**：旧方案按"与 controller 的距离"推算，那个距离不是布局常量
    # （0x28410 → -0x302080），会给出一个精确的错值。现在只复用钉值，
    # 且钉值只在签名库版本指纹匹配时才存在（换构建时整个库作废）。
    # **注意**：本函数上面已经从签名里拿到了 dwLocalPlayerPawn（它的访问器
    # 分散在几处，能截出 4 条），所以这里只在**没拿到**时才补钉值，
    # 否则报告里会出现两条同名条目，一个说可用、一个说需核对。
    pinned = (ss.hints.get("_pinned") or {}).get("dwLocalPlayerPawn")
    ctrl = next((v for v in verdicts if v.key == "dwLocalPlayerController"), None)
    have_pawn = any(v.key == "dwLocalPlayerPawn" and v.rva is not None
                    for v in verdicts)
    if pinned and not have_pawn:
        p = Verdict(key="dwLocalPlayerPawn", rva=pinned,
                    score=50, confident=False)
        p.notes.append("无代码引用，截不出签名（靠寄存器间接寻址，静态扫不到）")
        p.notes.append("复用上次联机在同一构建上核实过的值 %#x" % pinned)
        p.notes.append("只在 %s 这个构建有效；换了 DLL 必须重跑联机"
                       % (ss.version or "?"))
        verdicts.append(p)
    elif not have_pawn and ctrl and ctrl.rva is not None:
        verdicts.append(Verdict(
            key="dwLocalPlayerPawn", rva=None, score=0, confident=False,
            notes=["离线模式下算不出：该槽在 .text 里零 RIP 引用，"
                   "截不出签名，只能靠活进程的语义门定案"]))

    # convar 类（dwSensitivity / dwGameTypes）离线一律算不出：它们靠"活进程里
    # 那个对象的 +0x00 是不是自己的名字"定案，磁盘上的 DLL 里没有对象实例。
    # 但直接留空会让产物缺两条 —— 用的人把 deliver.ofs 覆盖过去，读表那边
    # 就少了这两个偏移，反而更难查。所以沿用基准里**上次联机核定过**的值，
    # 并明确标注来源，不冒充本次算出。
    for k in ("dwSensitivity", "dwGameTypes"):
        if any(v.key == k and v.rva is not None for v in verdicts):
            continue
        exp = EXPECT.get(k, {}).get("expect")
        if exp is None:
            continue
        cv_ = Verdict(key=k, rva=exp, score=60, expect=exp, confident=False)
        cv_.notes.append("convar 类：靠活进程读对象 +0x00 的名字自证，离线没法复算")
        cv_.notes.append("沿用上次联机核定值 %s+%#x（本模式未重算）"
                         % (EXPECT[k].get("module", "client.dll"), exp))
        verdicts.append(cv_)

    return {"ok": all(v.rva is not None for v in verdicts),
            "sigs": res, "verdicts": verdicts,
            "verdicts_out": verdicts}


def save_sigs(img, xr, res: dict, verbose: bool = True) -> str | None:
    """把这次联机解出的真值转成签名存盘，供下次离线用。

    同时记下**结构提示**：对每个全局，把它在签名候选族里的相对下标记下来。
    下次离线扫出同样一族候选时，直接按位置认 —— 这解决了
    "5 个同族 thunk 票数完全一样、签名无法定案"的问题。
    """
    targets = {v.key: v.rva for v in res["verdicts"]
               if v.rva is not None and v.key != "dwLocalPlayerPawn"}
    # dwLocalPlayerPawn 故意排除：它在 .text 里零引用（靠寄存器间接寻址），
    # 截不出签名。写进签名库只会得到一条命中 0 次的死签名。
    if not targets:
        return None
    ss = SigSet.extract(img, xr, targets, version=_dll_version(img))

    # 回扫一遍拿到候选族，才能算"真身在第几格"。
    # 这一步只用已知的 disp32（签名里已记录 expect），扫 2797 万字节约 6s。
    scanned = ss.solve(img, verbose=False)
    for key, rva in targets.items():
        slot = scanned.get(key)
        if not slot or len(slot["candidates"]) < 2:
            continue
        hint = SigSet.learn_hint(key, rva, slot["candidates"])
        if hint:
            ss.hints[key] = hint
            if verbose:
                print("  结构提示 %-24s 真身是族内第 %d 格（共 %d 格，间隔 %#x）"
                      % (key, hint["index"], hint["span"], hint["gap"]))

    # dwLocalPlayerPawn 在 .text 里零 RIP 引用（靠寄存器间接寻址），截不出签名。
    # **踩过的坑**：旧方案记"与 controller 的距离"当布局常量，2026-11-04 版
    # 实测 +0x28410，2026-11-06 更新后变成 **-0x302080**（跨了半个 .data），
    # 差了一个数量级 —— 距离根本不是不变量，据此推断只会给出一个精确的错值。
    # 改成：把本次联机**核实过**的值直接钉住，只在同一构建下复用
    # （签名库带版本指纹，换构建时整个作废，见 SigSet.load）。
    by_key = {v.key: v.rva for v in res["verdicts"]}
    pin = {k: by_key[k] for k in ("dwLocalPlayerPawn",)
           if by_key.get(k) is not None and k not in targets}
    if pin:
        ss.hints["_pinned"] = pin
        if verbose:
            print("  钉住 %s（同一构建下直接复用；换构建需重新联机）"
                  % ", ".join("%s=%#x" % (k, v) for k, v in pin.items()))

    path = str(CACHE_DIR / "sigs.json")
    ss.save(path)
    if verbose:
        print("\n签名库已更新：%d 条签名 + %d 条结构提示 → %s"
              % (len(ss.sigs), len(ss.hints), path))
    return path


def _dll_version(img) -> str:
    try:
        return "%08x" % (img.timestamp or 0)
    except Exception:
        return ""


# ---------------------------------------------------------------- 导出
def emit_ofs(res: dict, path: str, extra: dict[str, int] | None = None) -> str:
    """把结果写成 .ofs 偏移表（外部读表工具通用的纯文本格式）。

    格式要点（从现成 .ofs 表逆出来的）：
      * 每行 `Key = 0x值;`，`//` 后面是注释
      * 第一行固定 `Offsets_Date = "YYYY-MM-DD";`
      * 值全部是 **RVA**（相对模块基址），不是绝对地址

    `extra` 用来贴进这个工具解不出来的字段（比如从 schema 静态查的 m_* 偏移）。
    没解出的解一律不写 —— 宁可少一行，也不给使用者一个猜的值。
    """
    import datetime
    by = {v.key: v for v in res["verdicts"]}
    order = ["dwLocalPlayerController", "dwLocalPlayerPawn", "dwEntityList",
             "dwViewAngles", "dwViewMatrix", "dwGameTypes", "dwPlantedC4",
             "dwSensitivity"]
    L = ['Offsets_Date = "%s";' % datetime.date.today().isoformat(),
         "// 由 cs2re.auto 自动生成（%s），全部为 RVA，用时加模块基址"
         % (res.get("version") or "版本未知"),
         "// dwGameTypes 在 matchmaking.dll，其余在 client.dll"]
    n = 0
    for k in order:
        v = by.get(k)
        if not v or v.rva is None:
            continue
        note = ""
        if k in ("dwSensitivity", "dwGameTypes"):
            if v.confident:
                spec = EXPECT.get(k, {})
                note = "//%s convar 自报名验证" % spec.get("module", "client.dll")
            else:
                note = "//沿用上次联机核定值，本模式未重算"
        elif not v.confident:
            note = "//推测值，需联机核对"
        L.append("%s = %#x;%s" % (k, v.rva, note))
        n += 1
    if extra:
        L.append("")
        L.append("// ---- 以下为外部核定值（本模式算不出，来自联机核验记录）----")
        for k in sorted(extra):
            L.append("%s = %#x;" % (k, extra[k]))
            n += 1
    sv = res.get("schema") or []
    if sv:
        L.append("")
        L.append("// ---- m_* 字段（引擎类型表静态解出）----")
        for v in sv:
            if v.rva is None:
                continue
            mark = "" if v.agree else "//与基准 %#x 不同，需核对" % v.expect
            L.append("%s = %#x;%s" % (v.key, v.rva, mark))
            n += 1
    L.append("")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L), encoding="utf-8")
    return "%s（%d 条）" % (path, n)


def emit_header(res: dict, path: str, namespace: str = "cs2") -> str:
    """把结果写成 C++ 头文件 —— 拿着就能 include 进项目用。

    输出的都是 **RVA**（相对模块基址），不是绝对地址。用的时候：
        uintptr_t base = (uintptr_t)GetModuleHandleA("client.dll");
        auto vm = *(Matrix4x4*)(base + cs2::dwViewMatrix);
    ASLR 每次开游戏都变，所以绝对不能写死绝对地址。
    """
    keys = ["dwViewMatrix", "dwViewAngles", "dwEntityList",
            "dwLocalPlayerController", "dwLocalPlayerPawn",
            "dwSensitivity", "dwGameTypes"]
    by = {v.key: v for v in res["verdicts"]}
    L = ["// 由 cs2re.auto 自动生成，请勿手改。",
         "// client.dll 版本戳 %s" % (res.get("version") or "?"),
         "// 全部为 RVA，使用时加模块基址。",
         "#pragma once", "#include <cstdint>", "",
         "namespace %s {" % namespace, ""]
    for k in keys:
        v = by.get(k)
        if not v or v.rva is None:
            L.append("constexpr std::uintptr_t %s = 0x0;   // 未解出" % k)
            continue
        note = "" if v.confident else "   // 推测值/沿用值，需联机核对"
        L.append("constexpr std::uintptr_t %-24s = 0x%X;%s"
                 % (k, v.rva, note))
    L += ["", "}  // namespace %s" % namespace, ""]

    # 附带各偏移的典型用法，照着写就不会错
    L += ["/*  用法：",
          "    std::uintptr_t base = (std::uintptr_t)",
          "        GetModuleHandleA(\"client.dll\");",
          "",
          "    // 视角（两个 float：pitch, yaw）",
          "    float* angles = (float*)(base + cs2::dwViewAngles);",
          "",
          "    // 视图矩阵（4x4 float，行优先）",
          "    float* matrix = (float*)(base + cs2::dwViewMatrix);",
          "",
          "    // 实体列表（指针链：list -> chunk -> entity）",
          "    std::uintptr_t list = *(std::uintptr_t*)(base + cs2::dwEntityList);",
          "",
          "    // 本地玩家控制器 / 本体",
          "    std::uintptr_t ctrl = *(std::uintptr_t*)",
          "        (base + cs2::dwLocalPlayerController);",
          "    std::uintptr_t pawn = *(std::uintptr_t*)",
          "        (base + cs2::dwLocalPlayerPawn);",
          "*/", ""]

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L), encoding="utf-8")
    return path


def emit_json(res: dict, path: str) -> str:
    sv = res.get("schema") or []
    payload = {
        "version": res.get("version") or "",
        "dll": res.get("dll"),
        "elapsed": round(res.get("elapsed", 0.0), 1),
        "offsets": {v.key: (("%#x" % v.rva) if v.rva is not None else None)
                    for v in res["verdicts"]},
        "confident": {v.key: bool(v.confident) for v in res["verdicts"]},
        "detail": [{"key": v.key, "rva": v.rva, "score": v.score,
                    "dynamic": v.dynamic, "static": v.static,
                    "confident": v.confident, "notes": v.notes,
                    "expect": v.expect, "agree": v.agree,
                    "aliases": v.aliases}
                   for v in res["verdicts"]],
        # m_* 字段单独一块：它们走 schema 静态路径，与 dw_* 的证据链不同
        "schema_fields": {v.key: (("%#x" % v.rva) if v.rva is not None else None)
                          for v in sv},
        "schema_agree": sum(1 for v in sv if v.agree),
        "schema_total": len(sv),
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    return path


# ---------------------------------------------------------------- 主流程
def run(dll_path: str | None = None, pid: int | None = None,
        do_live: bool = True, verbose: bool = True,
        offline: bool = False) -> dict:
    t_all = time.time()
    path = dll_path or DEFAULT_DLL
    if not path:
        raise FileNotFoundError(
            "请指定 client.dll 路径：加 --dll <路径>，或设置环境变量 CS2RE_DLL")
    if not os.path.exists(path):
        raise FileNotFoundError("找不到 client.dll：%s" % path)

    print("=" * 68)
    print("CS2 全自动偏移扫描")
    print("=" * 68)
    img = pe.Image(path)
    print("DLL      : %s" % path)
    print("image_base %#x  size_of_image %#x" % (img.image_base, img.size_of_image))

    xr = load_xrefs(img, verbose=verbose)

    out: dict = {"dll": path, "verdicts": [], "elapsed": 0.0,
                 "static": {}, "ok": False, "version": _dll_version(img),
                 "schema": []}

    # ---- 第 0 阶段：schema 静态解 m_* 字段（不开游戏也能跑） ----
    try:
        sv = solve_schema_fields(img, verbose=verbose)
        out["schema"] = sv
    except Exception as exc:
        print("  ! schema 解析失败（不影响 dw_* 求解）：%s" % exc)

    if offline:
        off = solve_offline(img, xr, verbose=verbose)
        out.update(off)
        out["elapsed"] = time.time() - t_all
        return out

    if not do_live:
        # 只跑静态：报告给基准表里每个全局的引用数 —— 立刻能看出哪些是副本
        from .targets import TIER_B
        print("\n[静态] 基准表里各全局的代码引用情况")
        rows = []
        for k, (rva, desc) in TIER_B.items():
            n = xr.ref_count(rva)
            acc = xr.best_accessor(rva)
            rows.append({"key": k, "rva": rva, "refs": n,
                         "stride": acc["stride"] if acc else None,
                         "indexed": acc["indexed"] if acc else None,
                         "desc": desc})
            flag = "  ← 零引用（指针/数组槽常见，不等于假）" if n == 0 else ""
            print("  %-26s %#010x  引用 %-3d 步长 %s%s"
                  % (k, rva, n, ("%#x" % acc["stride"]) if acc and acc["stride"]
                     else "—", flag))
        out["static"] = rows
        out["elapsed"] = time.time() - t_all
        return out

    # ---- 活进程 ----
    proc: live.GameProcess
    # 先定进程再开句柄：pid 可能是上次的残留值，pick_process 会核对
    # 进程是否存在、名字是否对得上（防 PID 复用连到别的程序）。
    info = live.pick_process("cs2", pid)
    pid = info.pid
    proc = live.GameProcess(pid)
    try:
        print("PID      : %d" % pid)
        print("活基址   : %#x（PE 首选基址 %#x，ASLR 偏移 %+#x）"
              % (proc.base, img.image_base, proc.base - img.image_base))
        ok, msg = proc.verify_against(path)
        print("版本校验 : %s" % msg)
        if not ok:
            print("  ! 活模块与磁盘文件不一致，结果可能失效")

        dv = DataView(proc, img)
        print()

        vm = solve_viewmatrix(proc, img, dv, xr, verbose=verbose)
        out["verdicts"].append(vm)
        print("[1/5] dwViewMatrix            %-12s 分 %3d（动 %d + 静 %+d）%.1fs"
              % (vm.addr, vm.score, vm.dynamic, vm.static, vm.elapsed))

        va = solve_viewangles(proc, img, dv, xr, vm.rva, verbose=verbose)
        out["verdicts"].append(va)
        print("[2/5] dwViewAngles            %-12s 分 %3d（动 %d + 静 %+d）%.1fs"
              % (va.addr, va.score, va.dynamic, va.static, va.elapsed))

        es = solve_entity_list(proc, img, dv, xr, verbose=verbose)
        out["verdicts"].append(es)
        print("[3/5] dwEntityList            %-12s 分 %3d（动 %d + 静 %+d）%.1fs"
              % (es.addr, es.score, es.dynamic, es.static, es.elapsed))

        lc = solve_local_player(proc, img, dv, xr, es.rva, "controller",
                                verbose=verbose)
        out["verdicts"].append(lc)
        print("[4/5] dwLocalPlayerController %-12s 分 %3d（动 %d + 静 %+d）%.1fs"
              % (lc.addr, lc.score, lc.dynamic, lc.static, lc.elapsed))

        # 解 pawn 时必须把 controller 的**实体索引**传下去：主菜单下实体表里
        # 有好几个满血玩家 pawn，通用门会给出 4 个满分候选，只有"本地
        # controller 指向谁"能区分（2026-11-06 实测）。
        cidx = None
        if lc.rva is not None:
            ents0, _ = gates.read_entities(proc, es.rva)
            val = struct.unpack("<Q", proc.read_rva(lc.rva, 8))[0]
            cidx = next((i for i, p in ents0.items() if p == val), None)
            if verbose:
                print("  controller 实体索引 = %s（用它锁定 pawn）"
                      % (cidx if cidx is not None else "未在表内"))
        lp = solve_local_player(proc, img, dv, xr, es.rva, "pawn",
                                verbose=verbose, must_be=cidx)
        out["verdicts"].append(lp)
        print("[5/5] dwLocalPlayerPawn       %-12s 分 %3d（动 %d + 静 %+d）%.1fs"
              % (lp.addr, lp.score, lp.dynamic, lp.static, lp.elapsed))

        # ---- convar 类：名字自证，不参与打分竞争 ----
        print()
        print("[convar] 按对象自报名直接取槽位")
        for k in ("dwSensitivity", "dwGameTypes"):
            cv_ = solve_cvar(proc, img, k, verbose=verbose)
            out["verdicts"].append(cv_)
            print("  %-14s %s+%-9s 分 %3d  %.1fs"
                  % (k, EXPECT[k].get("module", "client.dll"), cv_.addr,
                     cv_.score, cv_.elapsed))
    finally:
        proc.close()

    out["elapsed"] = time.time() - t_all
    out["ok"] = all(v.rva is not None for v in out["verdicts"])

    # 联机成功就把真值转成签名存盘 —— 下次没开游戏也能算
    if out["ok"]:
        try:
            save_sigs(img, xr, out, verbose=verbose)
        except Exception as exc:
            print("  ! 签名库保存失败（不影响本次结果）：%s" % exc)
    return out


def report(res: dict) -> str:
    lines = []
    lines.append("")
    lines.append("=" * 68)
    lines.append("结果")
    lines.append("=" * 68)
    agree = [v for v in res["verdicts"] if v.agree is not None]
    for v in res["verdicts"]:
        mark = ""
        if v.agree is True:
            mark = "  ✓ 与基准一致"
        elif v.agree is False:
            mark = "  ✗ 与基准 %#x 不同" % v.expect
        lines.append("%-26s %-12s 分 %3d%s" % (v.key, v.addr, v.score, mark))
        for n in v.notes:
            lines.append("      · %s" % n)
        if len(v.candidates) > 1:
            others = [c for c in v.candidates[1:]
                      if c["rva"] != v.rva][:3]
            if others:
                s = ", ".join("%#x(分%d/静%+d)" % (c["rva"], c["score"], c["static"])
                              for c in others)
                lines.append("      次选：%s" % s)
    lines.append("")
    lines.append("总耗时 %.1fs" % res["elapsed"])
    if len(agree) == len(res["verdicts"]) and all(v.agree for v in agree):
        lines.append("全部 %d 项与基准表一致。" % len(agree))
    elif agree:
        lines.append("%d/%d 项与基准表一致。" % (sum(1 for v in agree if v.agree),
                                                len(agree)))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CS2 全自动偏移扫描")
    ap.add_argument("--dll", default=None, help="client.dll 路径")
    ap.add_argument("--pid", type=int, default=None, help="cs2.exe 的 PID")
    ap.add_argument("--no-live", action="store_true", help="只跑静态引用统计")
    ap.add_argument("--offline", action="store_true",
                    help="不开游戏，用签名库离线算（游戏更新后先跑这个）")
    ap.add_argument("--json", default=None, help="把结果写到这个 JSON 文件")
    ap.add_argument("--header", default=None,
                    help="把结果写成 C++ 头文件（如 offsets.hpp）")
    ap.add_argument("--ofs", default=None,
                    help="把结果写成 .ofs 偏移表（纯文本 Key = 0xRVA 格式）")
    ap.add_argument("--verify", action="store_true",
                    help="联机后再跑一遍活体验证（把 58 个 m_* 送去真实内存核对）")
    a = ap.parse_args(argv)

    try:
        res = run(a.dll, a.pid, do_live=not a.no_live, offline=a.offline)
    except Exception as exc:
        print("失败：%s" % exc, file=sys.stderr)
        return 1

    if a.offline:
        print(offline_report(res))
    elif not a.no_live:
        print(report(res))

    if a.json:
        emit_json(res, a.json)
        print("JSON 已写入 %s" % a.json)
    if a.header:
        emit_header(res, a.header)
        print("C++ 头文件已写入 %s" % a.header)
    if a.ofs:
        print(" .ofs 已写入 %s" % emit_ofs(res, a.ofs))

    # 活体验证：把解出的偏移拿去真实内存逐条核对。
    # 这一步是闭环的最后一块 —— 静态只能证明"名字在这个位置"，
    # 只有活读能证明"这个位置在运行时确实是那个语义"。
    if a.verify and not a.no_live and not a.offline:
        try:
            info = live.pick_process("cs2", a.pid)
        except LookupError:
            info = None
        if info is None:
            print("\n! 找不到 cs2.exe，跳过活体验证")
        else:
            # 传的是**校验过**的 PID，不是命令行原值 —— 命令行那个可能是
            # 上次的残留值（游戏重开后 PID 会变）。
            # flush 必须加：不刷缓冲的话子进程的输出会先跑出来，
            # 这行字反而排在它后面，看起来像"先验证后选进程"。
            print("\n活体验证接 PID %d..." % info.pid, flush=True)
            rc = subprocess.call(
                [sys.executable,
                 str(Path(__file__).resolve().parent.parent / "verify_live.py"),
                 "--pid", str(info.pid)])
            if rc not in (0, 2):
                print("! 活体验证异常退出（code %d）" % rc)

    # 只把 .ofs 投递到 下载\cs2-re\：那里是"要用的东西"的落脚点，
    # 不是日志仓库。hpp / json 留在 out\ 给需要的人自己拿。
    got = rpt.publish([p for p in (a.ofs, a.header, a.json) if p])
    if got:
        # 顺手清掉历次扫描留下的 txt 和旧副本：下载目录里只留这一份 ofs。
        gone = rpt.prune(rpt.out_dir(), {g.name for g in got})
        print("\n已投递到下载目录：")
        for g in got:
            print("  %s" % g)
        if gone:
            print("  已清理旧文件 %d 个" % len(gone))
    return 0


def offline_report(res: dict) -> str:
    lines = ["", "=" * 68, "离线结果（基于签名库，未接活进程）", "=" * 68]
    if not res.get("ok"):
        lines.append("没有结果：%s" % res.get("reason", "签名库缺失或全部未命中"))
        return "\n".join(lines)
    for v in res["verdicts"]:
        lines.append("%-26s %-12s %s" % (v.key, v.addr,
                                         "可直接使用" if v.confident
                                         else "需联机确认"))
        for n in v.notes:
            lines.append("      · %s" % n)
    lines.append("")
    lines.append("总耗时 %.1fs" % res["elapsed"])
    low = [v.key for v in res["verdicts"] if not v.confident]
    if low:
        lines.append("以下 %d 项本模式给不出独立证据，已标注来源，"
                     "拿不准就开着游戏跑一次联机模式定案：%s"
                     % (len(low), ", ".join(low)))
    else:
        lines.append("全部 %d 项已定案，无需开游戏。" % len(res["verdicts"]))
    return "\n".join(lines)


if __name__ == "__main__":
    # 屏幕照打，同时落一份 txt 到 下载\cs2-re\；out\ 里的成品也复制过去。
    if rpt.enabled():
        with rpt.capture("auto-scan"):
            _rc = main()
        raise SystemExit(_rc)
    raise SystemExit(main())
