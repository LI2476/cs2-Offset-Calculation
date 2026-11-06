"""Tier B：全局槽位（dwEntityList / dwLocalPlayerPawn / dwViewMatrix ...）。

这些不是"某个类里的字段"，而是 .data 里的裸槽位。难点在于：
**纯静态看不出来**。一个 8 字节 qword，可能是指针，可能是两个 int32，
可能只是常量池的一部分。没有类型信息，静态分析只能给候选。

所以 Tier B 的做法是：**静态缩范围 + 活进程验证**。
  1. 静态：从 .data 里筛出"内容像指针"或"形状像矩阵"的槽 —— 单靠这步不准，
     但能把 76 万个 8 字节槽压到几百个。
  2. 活进程：对每个候选跑语义门（矩阵门的正交归一、实体表的 vtable+场景坐标、
     本地玩家的双向量闭合），过门才算。
  3. 分组：**按"指向的对象"归并**。同一个 entity-system 对象在 .data 里
     常常有 2~3 个槽同时引用它（全局单例的别名），它们是等价答案，
     不该当成三个互相竞争的候选。

性能：所有扫描都基于 `dataview.DataView` —— 一次 ReadProcessMemory 把整个
.data（5.9 MB）拉进内存，之后全在本地 numpy 里跑。实测 0.006 秒读盘，
整轮 Tier B 扫描从 90 秒降到 35 秒（剩余时间花在二级解引用上）。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

import numpy as np

from . import gates
from .dataview import DataView
from .live import GameProcess
from .pe import Image

HEAP_LO = 0x10000
HEAP_HI = 0x7FFFFFFFFFFF
# 矩阵快筛（实测真值 row1 = [0, 0, 1.3333, tz]）：
#   行1 的 x/y 是"投影偏移"，正常帧为 0，转头过渡帧可到 0.16；
#   row1[2] 是宽高比，**不是 0**。旧版本把 f[6]==0 当快筛条件，会误杀真值。
VM_Q_XY = 0.35
VM_Q_ASPECT_LO = 0.4
VM_Q_ASPECT_HI = 3.0


@dataclass
class Slot:
    rva: int
    value: int | None          # 槽内容（矩阵为 None）
    score: int = 0
    reason: str = ""
    tags: list[str] = field(default_factory=list)
    group: int | None = None   # 归并组号（同一个被引用对象）
    key: tuple | None = None   # 归并键（矩阵用它存 16 个 float）

    @property
    def addr(self) -> str:
        return "%#010x" % self.rva


def _q(img: Image, rva: int) -> int | None:
    b = img.read(rva, 8)
    return struct.unpack("<Q", b)[0] if b else None


def _module_ranges(img: Image) -> list[tuple[int, int]]:
    """这个模块自己的 VA 区间（用来判断"指向模块内部的指针"）。"""
    return [(img.image_base + s.va, img.image_base + s.va + max(s.vsize, 0x1000))
            for s in img.sections]


def view(proc: GameProcess, img: Image) -> DataView:
    return DataView(proc, img)


def demote_array_members(hits: list[Slot], max_stride: int = 0x4000,
                         tol: int = 0x40) -> list[Slot]:
    """把"等距数组里的成员"降权。

    实测 dwViewAngles 那一轮出来 16 个候选，值完全一样（同一帧的 (pitch,yaw)
    被引擎写到十几处）。其中 0x25C4B70..0x25C8680 这 10 个间距精确等于 0x690，
    是某个结构的数组（每 tick 一份快照），**不是全局变量**。

    判据：如果存在另一个候选与之距离 D（D <= max_stride），且 D 的整数倍位置
    上还有候选，说明它们在同一个数组里 —— 全局单例不会有这种规律。
    数组成员扣 20 分，从 95 降到 75，落到阈值下。
    """
    rvas = sorted(s.rva for s in hits)
    inside: set[int] = set()
    for a in rvas:
        for b in rvas:
            if b <= a:
                continue
            d = b - a
            if d > max_stride:
                continue
            third = b + d
            fourth = a - d
            if any(abs(x - third) <= tol for x in rvas) or \
               any(abs(x - fourth) <= tol for x in rvas):
                inside.add(a)
                inside.add(b)
    for s in hits:
        if s.rva in inside and "array_member" not in s.tags:
            s.score = max(0, s.score - 20)
            s.tags.append("array_member")
            s.reason += "；与其它候选呈等距 → 疑为结构数组成员"
    return hits


def group_by_value(slots: list[Slot], tol: float = 1e-3) -> list[list[Slot]]:
    """按"指向同一个对象 / 数值上相等"归并。

    两种归并语义：

      * **指针槽**（value 是地址）：精确相等才归并。实测 dwEntityList 在 .data
        里有 3 个槽（0x23bfa10 / 0x254fe18 / 0x271eba8）同指 0x3186f471000，
        dwLocalPlayerController 有 2 个槽（0x21d6f50 / 0x2541538）同指
        0x318f5fdf000 —— 它们是同一全局单例的别名，算一个答案。

      * **矩阵槽**（value is None）：按矩阵内容近似相等归并。实测真值
        0x256f250 与 0x257dc68 的 16 个 float 只差 ~1e-7（同一矩阵的两份拷贝），
        精确比较分不开，用 tol 归并。
    """
    groups: list[list[Slot]] = []
    keys: list[object] = []

    def same(a: object, b: object) -> bool:
        if a is None or b is None:
            return a is b
        if isinstance(a, tuple) and isinstance(b, tuple):
            if len(a) != len(b):
                return False
            return all(abs(x - y) <= tol for x, y in zip(a, b))
        return a == b

    for s in slots:
        k = s.value if s.value is not None else s.key
        for gi, gk in enumerate(keys):
            if same(k, gk):
                groups[gi].append(s)
                break
        else:
            groups.append([s])
            keys.append(k)

    groups.sort(key=lambda g: (-max(x.score for x in g), min(x.rva for x in g)))
    for gi, arr in enumerate(groups):
        arr.sort(key=lambda s: s.rva)
        for s in arr:
            s.group = gi
    return groups


# ------------------------------------------------------------- 静态初筛
def candidates_by_pattern(img: Image, pattern: bytes, mask: bytes | None = None,
                          limit: int = 200) -> list[int]:
    """按"字节模式"找槽位返回 RVA 列表。mask 里 0x00 = 通配。"""
    out = img.find_bytes(pattern, mask=mask) if mask else img.find_bytes(pattern)
    return [img.to_rva(a) for a in out][:limit]


# ------------------------------------------------------------- 矩阵门（活）
def scan_viewmatrix(proc: GameProcess, img: Image, rva_lo: int, rva_hi: int,
                    step: int = 8, expect_angles=None, dv: DataView | None = None,
                    verbose: bool = False, fresh_read: bool = True) -> list[Slot]:
    """在 [rva_lo, rva_hi) 里按 8 字节步长找 4x4 投影矩阵。

    每 8 字节都试一次，因为矩阵不一定 16 字节对齐（实测真值 0x256f250 是对齐的，
    但同族副本 0x257dc68 不是）。

    快筛看的是 row1（索引 4..7）：x/y 接近 0、z 是宽高比。
    **不要再拿 f[2]/f[6]/f[10]==0 快筛** —— row1[2] 实测是 1.3333，
    那样会把真值自己筛掉（这是修过的一个真实 bug）。

    `fresh_read=True`（默认）时，候选判分前会**现读一次内存**。
    快照是整段 .data 一次读下来的（5.9 MB），游戏在这期间原地改矩阵，
    就会拼出**半旧半新**的 64 字节 —— 实测抓到过
    row0 = [-6.379, -9.484, 0, 16012]、|row0| = 11.43 这种撕裂值，
    连快筛都过不去（真值被自己筛掉，整轮 0 命中）。现读一次就干净了。
    """
    if dv is None:
        dv = DataView(proc, img)
    # 矩阵是 float32 数组，必须用 4 字节粒度索引（rva_to_idx32），
    # 用 8 字节粒度的 rva_to_idx 会把每个候选错位一半（踩过）。
    lo = max(0, dv.rva_to_idx32(rva_lo))
    hi = min(len(dv.f32), dv.rva_to_idx32(rva_hi))
    if hi <= lo:
        return []
    f32 = dv.f32
    idxs = np.arange(lo, hi - 15, max(step // 4, 1), dtype=np.int64)
    if idxs.size == 0:
        return []

    def _prescreen(xy_max: float | None) -> np.ndarray:
        sub = f32[idxs[:, None] + np.arange(16, dtype=np.int64)[None, :]]
        ok = (sub[:, 6] > VM_Q_ASPECT_LO) & (sub[:, 6] < VM_Q_ASPECT_HI)
        if xy_max is not None:
            ok &= (np.abs(sub[:, 4]) < xy_max) & (np.abs(sub[:, 5]) < xy_max)
        return idxs[ok]

    def _judge(cand) -> list[Slot]:
        out: list[Slot] = []
        for i in cand:
            if fresh_read:
                got = proc.read_rva(int(dv.rva + i * 4), 64)
                if not got:
                    continue
                f = list(struct.unpack("<16f", got))
            else:
                f = f32[i:i + 16].astype(np.float64).tolist()
            rows = [f[0:4], f[4:8], f[8:12], f[12:16]]
            g = gates.gate_viewmatrix(rows)
            if g.score < 80:
                continue
            if expect_angles is not None:
                ag = gates.gate_viewangles(
                    gates.angles_from_forward(gates.matrix_forward(rows)), expect_angles)
                g = gates.GateResult(min(g.score, ag.score), g.reason + "；角度 " + ag.reason,
                                     g.tags + ag.tags)
                if g.score < 80:
                    continue
            out.append(Slot(int(dv.rva + i * 4), None, g.score, g.reason, list(g.tags),
                            key=tuple(f)))
        return out

    # ---- 快筛：先不看 row1 的 x/y ----
    # **踩过的坑（两层）**：
    # 1) 只用严格 x/y 阈值（0.35）时，撕裂帧里真值 row1 = (9.76, -6.57) 会被自己筛掉；
    # 2) 改成"严格失败才放宽"也不行 —— 撕裂时严格阈值恰好命中了同族副本
    #    0x257dc68，hits 非空，放宽分支永不触发，真值照样丢。
    # 所以现在**默认不看 x/y**，只用「row1[2] 是宽高比 + row2 范数≈1」筛。
    # 实测候选从 5326 降到 3 个（当前分辨率 1.1188），而且撕裂帧也救得回来。
    # 最后再兜一层：一个候选都没有时才退回带 x/y 的宽筛。
    cand = _prescreen(None)
    hits = _judge(cand)
    if not hits:
        cand = _prescreen(VM_Q_XY * 25.0)
        hits = _judge(cand)
        if verbose and hits:
            print("  矩阵快筛放宽后救回 %d 个（无 x/y 筛时 0 命中）" % len(hits))
    if verbose:
        print("  矩阵扫描：快筛 %d 个候选，过 80 分 %d 个%s"
              % (cand.size, len(hits), "（现读复核）" if fresh_read else ""))
    return hits


# ------------------------------------------------------------- 视角度门（活）
def scan_viewangles(proc: GameProcess, img: Image, rva_lo: int, rva_hi: int,
                    expect: tuple[float, float] | None, step: int = 8,
                    dv: DataView | None = None, verbose: bool = False,
                    window: float = 5.0, fresh_read: bool = True,
                    stale: bool = False) -> list[Slot]:
    """找 (pitch, yaw) 这对 float，要求与矩阵反推的角度一致。

    **必须带第二证据**：.data 里"双非零且范围合法"的 float 对实测有 1814 个，
    光靠范围门毫无区分度。矩阵反推一致性才是唯一有说服力的判据。

    `fresh_read=True`（默认）时，候选判分前会**现读一次内存**，而不是用快照。
    这是必需的：dv 是 .data 的快照，矩阵却是刚读的，玩家转视角时两者差好几度
    —— 实测快照里的 (4.55, 77.81) 与实时 (5.39, 74.02) 差了 3.8 度，真身
    直接过不了预筛（跑出过"20 个候选、过 80 分 0 个"的空结果）。

    `window` 是预筛窗口（度）。快照脏的时候放大会捞回真身，代价只是多几个候选。

    `stale=True` 表示**调用方已经确认这份快照过期了**（玩家在转视角，快照里的
    角度值和实时值差几十度），此时跳过按值的窗口预筛，只按范围筛，逐条现读。
    实测过期快照里角度值会冻结在某一刻（比如一直停在 (0.61, 2.23)），
    真实值 (4.45, -112.12) 差了 114 度，任何窗口都捞不到。
    """
    if dv is None:
        dv = DataView(proc, img)
    if expect is None:
        return []
    lo = max(0, dv.rva_to_idx32(rva_lo))
    hi = min(len(dv.f32), dv.rva_to_idx32(rva_hi))
    if hi <= lo + 2:
        return []
    f32 = dv.f32
    idxs = np.arange(lo, hi - 1, max(step // 4, 1), dtype=np.int64)
    if idxs.size == 0:
        return []
    with np.errstate(invalid="ignore"):
        a = f32[idxs].astype(np.float64)
        b = f32[idxs + 1].astype(np.float64)

    def _prescreen(win: float | None) -> np.ndarray:
        finite = np.isfinite(a) & np.isfinite(b)
        ok = finite.copy()
        sel = finite
        if sel.any():
            m = (np.abs(a[sel]) <= 90.0) & (np.abs(b[sel]) <= 180.0)
            if win is not None:
                m &= (np.abs(a[sel] - ep) < win) & \
                     (np.abs((b[sel] - ey + 180.0) % 360.0 - 180.0) < win)
            ok[sel] = m
        return idxs[ok]

    def _judge(cand) -> list[Slot]:
        out: list[Slot] = []
        for i in cand:
            if fresh_read:
                got = proc.read_rva(int(dv.rva + i * 4), 8)
                if not got:
                    continue
                p, y = struct.unpack("<2f", got)
            else:
                p, y = float(f32[i]), float(f32[i + 1])
            g = gates.gate_viewangles((p, y), expect)
            if g.score >= 80:
                out.append(Slot(int(dv.rva + i * 4), None, g.score, g.reason,
                                list(g.tags), key=(p, y)))
        return out

    ep, ey = expect
    # 三级兜底：窗口筛 → 放宽窗口 → 完全不看快照的值，只筛范围后逐条现读。
    # **最后一级是必需的**：dv 是启动时读的快照，玩家一直在转视角。实测快照里的
    # 角度值一直冻结在 (0.61, 2.23)，而实时 (4.45, -112.12) 已经差了 114 度，
    # 任何按窗口的预筛都捞不到真身（连 60 度窗口都是 0 命中）。
    if stale:
        cand = _prescreen(None)
        hits = _judge(cand)
        if verbose and hits:
            print("  快照已过期（转视角中），改为范围筛 + 逐条现读，得 %d 个" % len(hits))
    else:
        cand = _prescreen(window)
        hits = _judge(cand)
        if not hits:
            cand = _prescreen(None)
            hits = _judge(cand)
            if verbose and hits:
                print("  视角窗口没捞到，改为范围筛 + 逐条现读，救回 %d 个" % len(hits))
    if verbose:
        print("  视角扫描：%d 个 float 对进入精验，过 80 分 %d 个%s"
              % (cand.size, len(hits), "（现读复核）" if fresh_read else ""))
    return hits


# ------------------------------------------------------------- 实体表门（活）
def scan_entity_list(proc: GameProcess, img: Image, rva_lo: int, rva_hi: int,
                     h_controller: int, h_player_pawn: int,
                     step: int = 8, dv: DataView | None = None,
                     mod_base: int | None = None, mod_size: int = 0,
                     verbose: bool = False) -> list[Slot]:
    """找"槽 -> ES* -> +0x10 -> 数组"这条链，且实体表过 vtable + 场景坐标门。

    mod_base 一定要传**实际加载基址**（proc.base），不是 PE 首选基址 —— 两者
    差 0x1c10660，用错了 vtable 判据会把真值判成 0 命中（真实踩过的坑）。
    """
    if dv is None:
        dv = DataView(proc, img)
    if mod_base is None:
        mod_base, mod_size = proc.base, img.size_of_image
    lo = max(0, dv.rva_to_idx(rva_lo))
    hi = min(len(dv.q), dv.rva_to_idx(rva_hi))
    if hi <= lo:
        return []
    q = dv.q
    m = dv.heap_ptr_mask() & (q > HEAP_LO) & (q < HEAP_HI)
    m[:lo] = False
    m[hi:] = False
    idxs = np.flatnonzero(m)
    hits: list[Slot] = []
    for i in idxs:
        # idxs 是 **qword 下标**，换算成 RVA 必须乘 8（少了这个乘法会让
        # 所有候选错位到 1/8 处，真值永远不在候选里 —— 踩过的真实 bug）。
        rva = int(dv.rva + i * 8)
        g = gates.gate_entity_list(proc, rva, h_controller, h_player_pawn,
                                   mod_base=mod_base, mod_size=mod_size)
        if g.score >= 80:
            hits.append(Slot(rva, int(q[i]), g.score, g.reason, list(g.tags)))
    if verbose:
        print("  实体表扫描：%d 个像指针的槽，过 80 分 %d 个" % (idxs.size, len(hits)))
    return hits


# ------------------------------------------------------------- 本地玩家门（活）
def scan_local_player(proc: GameProcess, img: Image, rva_lo: int, rva_hi: int,
                      ents: dict[int, int], h_controller: int, h_player_pawn: int,
                      want: str = "controller", step: int = 8,
                      dv: DataView | None = None, verbose: bool = False,
                      must_be: int | None = None) -> list[Slot]:
    """找"值等于实体表里某个实体"的槽，并要求双向量闭合。

    `must_be` = 已知的 controller 实体索引。解 pawn 时必须传它：主菜单下
    实体表里有好几个 maxHealth=100 的玩家 pawn，通用门会给出 4 个满分候选，
    只有"本地 controller 指向哪个"能定案（详见 gates.gate_local_player）。
    """
    if dv is None:
        dv = DataView(proc, img)
    lo = max(0, dv.rva_to_idx(rva_lo))
    hi = min(len(dv.q), dv.rva_to_idx(rva_hi))
    ptrs = sorted(set(ents.values()))
    if not ptrs:
        return []
    arr = np.array(ptrs, dtype=np.uint64)
    q = dv.q
    seg = q[lo:hi]
    pos = np.searchsorted(arr, seg)
    pos = np.clip(pos, 0, len(arr) - 1)
    ok = arr[pos] == seg
    cand = np.flatnonzero(ok) + lo
    hits: list[Slot] = []
    for i in cand:
        # cand 是 qword 下标，RVA 必须乘 8
        rva = int(dv.rva + i * 8)
        g = gates.gate_local_player(proc, rva, ents, h_controller, h_player_pawn,
                                    want=want, must_be=must_be)
        if g.score >= 80:
            hits.append(Slot(rva, int(q[i]), g.score, g.reason, list(g.tags)))
    if verbose:
        print("  本地玩家(%s)：%d 个槽值落在实体表里，过 80 分 %d 个"
              % (want, cand.size, len(hits)))
    return hits
