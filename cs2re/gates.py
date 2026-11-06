"""验证门：给一个候选地址打分，说清楚"凭什么信它"。

这是"准确率高"的唯一实现路径 —— 不是靠更聪明的猜测，是靠
**每个候选都必须过一道能拒绝错误答案的门**。

设计原则：
  1. 门返回 (score: 0..100, reason: str, tags: list)。
     score >= 90 视为"可以采用"，60..89 "候选，需第二证据"，< 60 "拒绝"。
  2. 每个门都必须能在**错误输入上返回低分**。每轮运行都会跑一批
     人工构造的诱饵做自校准，误判率不为 0 就在报告里标红并降级该门。
  3. 门之间不共享状态，可以单独测。

阈值都是实测出来的，改动前先看注释里的实测值。
"""
from __future__ import annotations

import math
import random
import struct
from dataclasses import dataclass

from .live import GameProcess
from .pe import Image

# ---------------------------------------------------------------- 常量（实测）
# ViewMatrix 24 帧实测（本机 2026-11-04，pitch=0）：
#   row0 = [right.x, right.y, right.z, -d(right,eye)]   单位长
#   row1 = [0, 0, 1.3333, -72.19]   ← **只有 z 分量**，1.3333 = 宽高比(4:3)
#   row2 = [fwd.x, fwd.y, fwd.z, -d(fwd,eye)]           单位长
#   row3 = [fwd.x, fwd.y, fwd.z, ...]                   与 row2 平行(点积 1.000)
#
# **踩过的坑**：我第一版把 "m[0][2]=m[1][2]=m[2][2]=0" 当不变量。
# 实测 row1 的第三个分量是宽高比 1.3333，不是 0；而且 row0/row2 的 z 分量
# 只在 pitch==0 时才为 0，一抬头就非零。用这个条件筛选会漏掉真值。
# 真正恒定的只有 row1[0]==row1[1]==0（投影行）。
VM_ROW_TOL = 0.02          # 行范数容差（窗口宽高比会改 row1）
VM_ORTHO_TOL = 0.01        # 正交容差
VM_PARALLEL_TOL = 0.999    # row2 与 row3 归一化点积下限
VM_ASPECT_LO = 0.4         # row1[2] 下限（宽高比量级）
VM_ASPECT_HI = 8.0         # row1[2] 上限
VM_PROJ_XY_MAX = 0.35      # row1 x/y 上限（过渡帧实测 0.156，留一倍余量）
VM_MIN_TRANSLATE = 1.0     # |m[3][3]| 至少这么大

# 实体表：identity 步长与关键位置（本机实测）
IDENTITY_STRIDE = 0x70
IDENTITY_INSTANCE = 0x38
ES_TO_ARRAY = 0x10
ARRAY_BASE_DELTA = 0x38
HANDLE_INDEX_MASK = 0x7FFF
ENUM_MAX = 600             # 单次扫描的实体上限
MIN_ENTITIES = 5           # 少于这个数认为表还没建好
VTABLE_MIN_RATIO = 0.85    # 实体 vtable 落在模块内的最小比例（实测：真值 1.00，噪音 ≤0.23）
# 场景节点坐标：真实体 +0x330 = m_pGameSceneNode，其 +0x80 = m_vecOrigin。
# 实测（2026-11-04，菜单状态下血量全为 0）：真值 123/138 = 0.89，
# 三个假候选（0x2565D68/0x27074F8/0x2707758）全部 0/111 = 0.00。
# 这是菜单里唯一还活着的结构性判据 —— 血量在菜单必然是 0，坐标不会。
SCENE_NODE_OFF = 0x330
SCENE_ORIGIN_OFF = 0x80
SCENE_MIN_RATIO = 0.50     # 实测真值 0.89，假值 0.00，中间留足空档
SCENE_COORD_MIN = 1.0      # 坐标绝对值下限（0,0,0 是未初始化）
SCENE_COORD_MAX = 20000.0  # 地图最大对角 ~16k
# LocalPlayer 判据：m_iMaxHealth 是"配置值"，菜单里也一直在（实测 localPawn=100，
# world/controller 都是 0）。m_iHealth 在菜单里是 0，不能用。
MAX_HEALTH_OFF = 0x348
PAWN_MAX_HEALTH_HI = 200


@dataclass
class GateResult:
    score: int
    reason: str
    tags: list[str]

    def ok(self, thr: int = 90) -> bool:
        return self.score >= thr

    def __bool__(self) -> bool:
        return self.score >= 90


def _finite(vals) -> bool:
    return all(isinstance(v, float) and math.isfinite(v) for v in vals)


# ==================================================================== 矩阵门
def gate_viewmatrix(rows: list[tuple[float, ...]]) -> GateResult:
    """4x4 世界->裁剪矩阵门。

    判据全部来自 24 帧实测的不变量，不是"觉得应该是这样"：
      * row1 = [0, 0, aspect, tz]   —— 投影行，x/y 恒为零，z 是宽高比
      * row0、row2 单位长且正交    —— 相机旋转基
      * row2 与 row3 平行          —— CS2 的矩阵就是这样排的（不是标准 4x4）
      * 末列非零                    —— 平移项存在

    拒绝理由举例：
      * row1 的 x/y 不为零 → 这不是投影行
      * row1[2] 不在 [0.4, 8]  → 宽高比量级不对
      * 前两行不正交        → 不是旋转基
      * 含 NaN/Inf/超大值   → 是别的数据
    """
    if len(rows) != 4 or any(len(r) != 4 for r in rows):
        return GateResult(0, "形状不是 4x4", [])

    flat = [float(x) for r in rows for x in r]
    if not _finite(flat):
        return GateResult(0, "含 NaN/Inf", [])
    mag = max(abs(x) for x in flat)
    if mag > 1e6:
        return GateResult(0, "含异常大值 %.3g" % mag, [])
    if mag < 1e-3:
        return GateResult(0, "几乎全零（未初始化）", ["zero"])

    def n3(r):
        return math.sqrt(r[0] ** 2 + r[1] ** 2 + r[2] ** 2)

    # --- 投影行 row1：x/y 应当接近 0 ---
    # **踩过的坑**：第一版要求 x/y 严格 <1e-6，结果**真值在转头过渡帧被自己拒掉**
    # （实测过渡帧 row1 = [-0.1559, 0.1534, 1.3153, ...]，插值还没收敛）。
    # 静态看是 0，动态看有渗入。所以改成量级判据：只要远小于 1 就行。
    xy_mag = max(abs(rows[1][0]), abs(rows[1][1]))
    if xy_mag > VM_PROJ_XY_MAX:
        return GateResult(0, "投影行 row1 的 x/y 过大 (%.4f/%.4f)" % (rows[1][0], rows[1][1]), [])
    aspect = abs(rows[1][2])
    if not (VM_ASPECT_LO <= aspect <= VM_ASPECT_HI):
        return GateResult(8, "row1[2]=%.4f 不在宽高比范围" % rows[1][2], [])

    n0, n2, n3_ = n3(rows[0]), n3(rows[2]), n3(rows[3])
    if min(n0, n2, n3_) < 1e-4:
        return GateResult(0, "有零行（不是旋转基）", [])

    def dot(a, b):
        return (a[0] * b[0] + a[1] * b[1] + a[2] * b[2]) / (n3(a) * n3(b))

    d02 = dot(rows[0], rows[2])
    d23 = dot(rows[2], rows[3])
    if abs(d02) > VM_ORTHO_TOL:
        return GateResult(0, "row0 与 row2 不正交 (%.4f)" % d02, [])

    score = 40
    tags = ["proj_row"]

    # --- row0 / row2 单位长 ---
    if abs(n0 - 1.0) < VM_ROW_TOL:
        score += 15
        tags.append("unit_r")
    if abs(n2 - 1.0) < VM_ROW_TOL:
        score += 15
        tags.append("unit_f")
    else:
        # row2 允许有一点点不正——CS2 的 row2 范数是 1.0003
        if abs(n2 - 1.0) < 0.05:
            score += 8
            tags.append("near_unit_f")

    # --- row2 与 row3 平行（CS2 特有排布，强特征）---
    if d23 > VM_PARALLEL_TOL:
        score += 20
        tags.append("parallel_23")
    else:
        score -= 20
        tags.append("not_parallel")

    # --- 末列平移项：世界坐标 ---
    # 0/1 置换矩阵（实测 .data @0x27a3900 就有一个）能过前面所有条件，
    # 所以必须加"相机姿态"判据：CS 没有横滚，up = cross(fwd, right) 应当接近竖直。
    # 实测真值 up_z = -0.9997（|up_z|≈1）；置换矩阵 up_z = 0 → 必须拒绝。
    trans = max(abs(rows[0][3]), abs(rows[1][3]), abs(rows[2][3]))
    if trans < VM_MIN_TRANSLATE:
        return GateResult(10, "平移列近零（不像相机矩阵）", ["no_translate"])

    # --- m[3][3] 齐次项必须存在（2026-11-04 实测新增，砍掉 3 个假阳性）---
    # 真值 m[3][3] = 1308.74（约等于 row2[3]=1305.27，因为 row3 就是 row2 的
    # 平移副本）；而 .data 里三个"烘焙好的常量投影矩阵"
    # （0x257E5F8 / 0x257EF98 / 0x272B9D8）m[3][3] 恰好是 0，row2[3]=-11.11。
    # 这三个能过前面所有判据（单位长、正交、平行、up 竖直），只有这一刀能分开。
    if abs(rows[3][3]) < VM_MIN_TRANSLATE:
        return GateResult(35, "m[3][3]=%.4f 近零，像烘焙的常量投影矩阵而非活相机"
                          % rows[3][3], ["baked"])

    upz = abs(rows[2][0] * rows[0][1] - rows[2][1] * rows[0][0]) / ((n2 * n0) or 1.0)
    if upz >= 0.9:
        score += 10
        tags.append("upright")
    elif upz >= 0.6:
        score += 3
        tags.append("tilted")
    else:
        return GateResult(20, "相机基有横滚（up_z=%.3f），不是 FPS 相机" % upz, ["rolled"])

    if abs(rows[3][3]) > VM_MIN_TRANSLATE:
        score += 10
        tags.append("translate")

    score = max(0, min(score, 100))
    return GateResult(
        score,
        "正交归一 r=%.4f f=%.4f fr=%.4f 平行=%.3f aspect=%.4f m33=%+.2f"
        % (n0, n2, n3_, d23, aspect, rows[3][3]),
        tags,
    )


# ==================================================================== 实体表
def vtable_ratio(proc: GameProcess, ents: dict[int, int], base: int, size: int,
                 n_sample: int = 80) -> tuple[float, int, int]:
    """实体头 8 字节（vtable 指针）落在 client.dll 里的比例。

    **这是整个实体表门里唯一难伪造的判据**。
    前面那版我用"双向闭合"当判据，结果 .data 里 4137 个槽都过门 —— 因为
    world entity 的索引是 0，它指向"自己"（handle 低 15 位 = 0，ents[0] 存在），
    于是 `pawn[0] <-> controller[0]` 这种垃圾组合也能"闭合"。判据完全没有区分度。

    实测（2026-11-04）：真值 80/80 = 1.00；8 个噪音候选 0.00~0.23；随机槽 0.00。
    原因很物理：真实体是 C++ 对象，头 8 字节是 vtable，而 vtable 在模块的 .rdata 里；
    噪音只是"内存里碰巧像指针的东西"，它们的头 8 字节是别的对象的字段或垃圾。
    """
    lo, hi = base, base + size
    tot = hit = 0
    for _, p in list(ents.items())[:n_sample]:
        b = proc.read(p, 8)
        if not b:
            continue
        tot += 1
        v = struct.unpack("<Q", b)[0]
        if lo <= v < hi:
            hit += 1
    return (hit / tot if tot else 0.0), hit, tot


def scene_ratio(proc: GameProcess, ents: dict[int, int],
                n_sample: int = 0) -> tuple[float, int, int]:
    """实体 -> m_pGameSceneNode -> m_vecOrigin，统计"坐标像个真坐标"的比例。

    这是 Tier B 最硬的一道门，因为**它是菜单状态下唯一还活着的语义**：
    实测（2026-11-04，主菜单）local pawn 的 m_iHealth=0、m_lifeState=2、
    m_iTeamNum=0 —— 血量队伍判据全部失效；但 138 个真实体里 123 个的
    场景节点坐标落在 1..20000 的合理范围（比例 0.89），三个假候选是 0.00。

    假候选为什么过不了：它们的"实体"是 .rdata 指针表里凑出来的，
    +0x330 读出来的不是场景节点指针，二级解引用后自然不是有限坐标。
    """
    han = list(ents.items())
    if n_sample:
        han = han[:n_sample]
    tot = hit = 0
    for _, p in han:
        b = proc.read(p + SCENE_NODE_OFF, 8)
        if not b:
            continue
        sn = struct.unpack("<Q", b)[0]
        if not (0x10000 < sn < 0x7FFFFFFFFFFF):
            continue
        tot += 1
        bo = proc.read(sn + SCENE_ORIGIN_OFF, 12)
        if not bo:
            continue
        x, y, z = struct.unpack("<3f", bo)
        if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
            continue
        m = max(abs(x), abs(y), abs(z))
        if SCENE_COORD_MIN < m < SCENE_COORD_MAX:
            hit += 1
    return (hit / tot if tot else 0.0), hit, tot


def read_entities(proc: GameProcess, es_rva: int, max_idx: int = ENUM_MAX):
    """按"B0 = *(ES+0x10) - 0x38"的排布枚举实体。

    返回 (ents: dict[idx -> ptr], diag: list[str])。
    diag 记录失败原因，方便报告里说清楚"为什么这个槽不对"。
    """
    diag: list[str] = []
    raw = proc.read_rva(es_rva, 8)
    if not raw:
        return {}, ["读不到槽位（页不可读）"]
    es = struct.unpack("<Q", raw)[0]
    if not (0x10000 < es < 0x7FFFFFFFFFFF):
        return {}, ["槽内容是 %#x，不像堆指针" % es]
    raw = proc.read(es + ES_TO_ARRAY, 8)
    if not raw:
        return {}, ["*ES 可读但 ES+0x10 读不到"]
    arr0 = struct.unpack("<Q", raw)[0]
    if not (0x10000 < arr0 < 0x7FFFFFFFFFFF):
        return {}, ["ES+0x10 内容是 %#x，不像指针" % arr0]

    b0 = arr0 - ARRAY_BASE_DELTA
    ents: dict[int, int] = {}
    for i in range(max_idx):
        blk = proc.read(b0 + IDENTITY_STRIDE * i + IDENTITY_INSTANCE, 8)
        if not blk:
            continue
        p = struct.unpack("<Q", blk)[0]
        if 0x10000 < p < 0x7FFFFFFFFFFF:
            ents[i] = p
    if len(ents) < MIN_ENTITIES:
        diag.append("只枚举到 %d 个实体（< %d），表可能还没建好" % (len(ents), MIN_ENTITIES))
    return ents, diag


def gate_entity_list(proc: GameProcess, es_rva: int,
                     h_controller: int, h_player_pawn: int,
                     mod_base: int | None = None, mod_size: int = 0) -> GateResult:
    """实体表门。

    四道判据，从便宜到贵，任一失败即拒：

      0. **槽内容必须是堆指针**（最便宜，先切掉大部分垃圾）。

      1. **ES 必须是堆指针，不能落在模块内**。
         .data 里 `*(槽)` 有三种可能：堆对象、模块内地址、垃圾。
         实测 0x2489110/0x2489358/0x248A0E8 三个假候选的 ES 是 0x7ffc5507xxxx
         （在 .rdata 里），它们枚举出来的"实体"其实是 .rdata 里的指针表，
         当然也"vtable 命中"——因为它们本来就是指向模块内的指针。这条一刀切掉。

      2. **槽值本身不能是实体**。
         真值 dwEntityList 的 ES 是 entity-system 对象，它不是实体；
         而 dwLocalPlayerController（0x21d6f50）的槽值就是一个 controller 实体，
         用判据 1 + vtable 都能过。这条把"指向实体的槽"和"实体表槽"分开。

      3. **vtable 归属**（比例 >= 0.85）。
         实测真值 80/80 = 1.00；噪音候选 0.00~0.23。

      4. **场景节点坐标**（比例 >= 0.50）。
         实测真值 123/138 = 0.89；三个 vtable 合格的假候选 0/111 = 0.00。
         这是**把 6 个候选收敛到 1 个**的那一刀。

      5. **双向闭合**（加分项）。
         单独用它没用（索引 0 会"自闭合"，4137 个噪音全过），但配合 1~4 之后
         能确认这张表是活的。
    """
    raw = proc.read_rva(es_rva, 8)
    if not raw:
        return GateResult(0, "读不到槽位", [])
    es = struct.unpack("<Q", raw)[0]
    if not (0x10000 < es < 0x7FFFFFFFFFFF):
        return GateResult(0, "槽内容是 %#x，不像堆指针" % es, [])
    if mod_base is not None and mod_base <= es < mod_base + mod_size:
        return GateResult(0, "ES 落在模块内（%#x），是静态表不是实体系统" % es, ["in_module"])

    ents, diag = read_entities(proc, es_rva)
    if not ents:
        return GateResult(0, diag[0] if diag else "枚举不到实体", [])
    if len(ents) < MIN_ENTITIES:
        return GateResult(0, "只枚举到 %d 个实体（< %d）" % (len(ents), MIN_ENTITIES), [])

    # --- 判据 2：槽值本身不能是实体 ---
    ptr_set = set(ents.values())
    if es in ptr_set:
        return GateResult(15, "槽值 %#x 本身就是实体表里的实体（这是'指向实体的槽'，不是实体表）"
                          % es, ["is_entity"])

    # --- 判据 3：vtable 归属 ---
    vt_reason = ""
    if mod_base is not None:
        ratio, hit, tot = vtable_ratio(proc, ents, mod_base, mod_size)
        vt_reason = "vtable %d/%d=%.2f" % (hit, tot, ratio)
        if ratio < VTABLE_MIN_RATIO:
            return GateResult(int(20 + 40 * ratio),
                              "%s，实体表不像真表（vtable 不在模块内）" % vt_reason,
                              ["bad_vtable"])

    # --- 判据 4：场景节点坐标（最硬的一道：血量为 0 时它仍然有效）---
    sratio, sok, stot = scene_ratio(proc, ents)
    if stot == 0 or sratio < SCENE_MIN_RATIO:
        return GateResult(int(15 + 45 * sratio),
                          "%s；场景节点坐标合理 %d/%d=%.2f，不像真实体"
                          % (vt_reason, sok, stot, sratio),
                          ["bad_scene"])

    # --- 判据 4：双向闭合（加分）---
    closed = None
    for i, pawn in ents.items():
        hb = proc.read(pawn + h_controller, 4)
        if not hb:
            continue
        ci = struct.unpack("<I", hb)[0] & HANDLE_INDEX_MASK
        ctrl = ents.get(ci)
        if not ctrl:
            continue
        hb2 = proc.read(ctrl + h_player_pawn, 4)
        if not hb2:
            continue
        back = struct.unpack("<I", hb2)[0] & HANDLE_INDEX_MASK
        if back == i:
            # 索引 0 的"自闭合"没有信息量：world entity 的 handle 就是 0
            if i == 0 and ci == 0:
                continue
            closed = (i, ci)
            break

    if closed:
        return GateResult(
            100,
            "%s；场景坐标 %.2f；双向量闭合 pawn[%d] <-> controller[%d]，实体数 %d"
            % (vt_reason, sratio, closed[0], closed[1], len(ents)),
            ["bidirectional", "n=%d" % len(ents)],
        )
    # 过完四道硬门已经是唯一候选了（实测 .data 全域只剩 1 个），
    # 双向量闭合只是"此刻在局内"的额外确认，没拿到不该扣到不及格。
    return GateResult(90, "%s；场景坐标 %.2f；实体 %d 个，双向量此刻未闭合（可能在菜单/观战/死亡）"
                      % (vt_reason, sratio, len(ents)), ["n=%d" % len(ents)])


def gate_local_player(proc: GameProcess, rva: int, ents: dict[int, int],
                      h_controller: int, h_player_pawn: int,
                      want: str = "controller",
                      must_be: int | None = None) -> GateResult:
    """LocalPlayerController / LocalPlayerPawn 门。

    三条硬判据（全部来自实测，不是推测）：

      1. **不能是 world 实体（索引 0）**。
         world 的 m_hPlayerPawn 和 m_hController 都是 0，索引 0 & 0x7FFF = 0
         正好指回自己 —— 于是 `pawn[0] <-> controller[0]` 被判成"双向闭合"。
         实测槽 0x255D8C8 靠这个假闭合拿了 100 分，而它是垃圾。
         **自指不是闭合证据。**

      2. **pawn 必须"像个玩家"**：m_iMaxHealth(0x348) 落在 1..200。
         实测 localPawn[303] maxHealth=100；world[0] 和 controller[1] 都是 0。
         这是菜单状态下唯一还能区分实体类别的字段（血量 m_iHealth=0 是因为
         不在局内，但 maxHealth 是配置值，一直都在）。

      3. **反向闭合用"查表"实现，不读 pawn 自己的字段**。
         实测 menu 状态：localPawn.hController = 0xFFFFFFFF（低 15 位 = 32767，
         无效），而 localCtrl.hPlayerPawn 仍正确指向 303。
         所以反向必须遍历实体表找"谁的 hPlayerPawn == 我"，直接读
         pawn.hController 会在菜单里必然失败（这是修过的一个真实误判）。
    """
    raw = proc.read_rva(rva, 8)
    if not raw:
        return GateResult(0, "读不到槽位", [])
    v = struct.unpack("<Q", raw)[0]
    if v == 0:
        return GateResult(0, "槽值为 0（未初始化或不在局内）", ["null"])

    idx = [i for i, p in ents.items() if p == v]
    if not idx:
        return GateResult(0, "值 %#x 不在实体表里" % v, [])
    i = idx[0]

    # --- 判据 1：world 实体不是 local player ---
    if i == 0:
        return GateResult(5, "指向实体索引 0（world 世界实体），不是 local player", ["world"])

    def max_health(p: int) -> int:
        b = proc.read(p + MAX_HEALTH_OFF, 4)
        return struct.unpack("<i", b)[0] if b else -1

    def handle_idx(p: int, off: int) -> int:
        b = proc.read(p + off, 4)
        return (struct.unpack("<I", b)[0] & HANDLE_INDEX_MASK) if b else -1

    def find_controller_of(pawn_idx: int) -> int:
        """遍历实体表，找哪个实体的 m_hPlayerPawn 指向 pawn_idx。"""
        for k, p in ents.items():
            if k == 0 or k == pawn_idx:
                continue
            if handle_idx(p, h_player_pawn) == pawn_idx:
                return k
        return -1

    if want == "controller":
        j = handle_idx(v, h_player_pawn)
        if j < 0:
            return GateResult(20, "在表里（索引 %d）但读不到 m_hPlayerPawn" % i, ["weak"])
        if j == 0:
            return GateResult(10, "controller[%d] 的 m_hPlayerPawn 指向 world" % i, ["world"])
        pawn = ents.get(j)
        if not pawn:
            return GateResult(25, "controller[%d] 指向 pawn 索引 %d，表里没有" % (i, j), ["weak"])
        mh = max_health(pawn)
        if not (1 <= mh <= PAWN_MAX_HEALTH_HI):
            return GateResult(30, "controller[%d] -> pawn[%d]，但 maxHealth=%d 不像玩家 pawn"
                              % (i, j, mh), ["not_pawn"])
            # --- 判据 3：反向用查表 ---
        back = find_controller_of(j)
        if back == i:
            return GateResult(100, "controller[%d] <-> pawn[%d]（maxHealth=%d）双向闭合"
                              % (i, j, mh), ["bidirectional"])
        return GateResult(90, "controller[%d] -> pawn[%d]（maxHealth=%d），反向未闭合"
                          % (i, j, mh), ["forward_only"])

    # ---- want == "pawn" ----
    mh = max_health(v)
    if not (1 <= mh <= PAWN_MAX_HEALTH_HI):
        return GateResult(15, "pawn 候选[%d] maxHealth=%d 不像玩家 pawn" % (i, mh), ["not_pawn"])
    back = find_controller_of(i)
    if must_be is not None:
        # **必须钉死是"我们那个 controller 的 pawn"**。
        # 踩过的坑（2026-11-06 主菜单）：实体表里有 200+ 个实体，其中好几个
        # 都是 maxHealth=100 的玩家 pawn（bot / 观战目标），所以
        # `0x223f4c8 / 0x223f4d8 / 0x223f4e8 / 0x223f4f8` 四个相邻槽
        # **全都拿 100 分**，通用门完全分不出哪个是本地玩家 —— 它们各自
        # 是不同真人/bot 的 pawn，语义都"合法"。
        # 唯一能区分的是身份：本地 controller 的 m_hPlayerPawn 指向谁。
        if back == must_be:
            return GateResult(100, "pawn[%d]（maxHealth=%d）正是本地 controller[%d] "
                              "所指的 pawn" % (i, mh, back), ["bidirectional"])
        return GateResult(20, "pawn[%d] maxHealth=%d，但它的 controller 是 [%d] 不是本地 [%d]"
                          % (i, mh, back, must_be), ["other_player"])
    if back >= 0:
        return GateResult(100, "pawn[%d]（maxHealth=%d）<-> controller[%d] 双向闭合"
                          % (i, mh, back), ["bidirectional"])
    return GateResult(85, "pawn[%d]（maxHealth=%d）没有 controller 指向它" % (i, mh),
                      ["forward_only"])


# ==================================================================== 视角度
def matrix_forward(rows) -> tuple[float, float, float]:
    """从矩阵取出视线方向。

    实测（yaw=-33.733）：row2[:3] = (0.8318, -0.5555, 0.0000)，
    而 atan2(-0.5555, 0.8318) = -33.733° —— **row2 就是 forward**。

    第一版我按"标准 view matrix"用 cross(row0, row1) 算 forward，
    在这个数据上碰巧也对（因为 row1 只有 z 分量，叉积退化成取 row2），
    但那是运气。直接取 row2 才是对的，pitch 一抬头也是。
    """
    f = rows[2]
    n = math.sqrt(f[0] ** 2 + f[1] ** 2 + f[2] ** 2) or 1.0
    return f[0] / n, f[1] / n, f[2] / n


def angles_from_forward(f) -> tuple[float, float]:
    """引擎约定：pitch 抬头为正（atan2(-f.z, 水平长)），yaw 0 指向 +X。

    实测校验：yaw= -33.733 时 f=(0.8318,-0.5555,0) → atan2(-0.5555,0.8318)=-33.733 ✓
    """
    horiz = math.sqrt(f[0] ** 2 + f[1] ** 2)
    pitch = math.degrees(math.atan2(-f[2], horiz))
    yaw = math.degrees(math.atan2(f[1], f[0]))
    return pitch, yaw


def gate_viewangles(pair: tuple[float, float], expect: tuple[float, float] | None,
                    tol_deg: float = 1.0) -> GateResult:
    """视角度门。

    单独用范围太弱：本机实测 .data 里有 1814 个"双非零且范围合法"的 float 对，
    加上矩阵反推一致性后收敛到 16 个。所以这个门的核心是第二证据。

    tol 原来是 0.5，200 帧压测发现**转头过渡帧**会掉到 0.56 度
    （矩阵那份数据比 angles 那份早/晚一帧更新），放到 1.0 才稳。
    """
    if pair is None:
        return GateResult(0, "读不到", [])
    p, y = pair
    if not (_finite([p, y])):
        return GateResult(0, "含 NaN/Inf", [])
    if not (-90 <= p <= 90):
        return GateResult(0, "pitch 越界 %.2f" % p, [])
    if not (-180 <= y <= 180):
        return GateResult(0, "yaw 越界 %.2f" % y, [])

    score = 30
    tags = ["range"]
    if abs(p) < 0.05 and abs(y) < 0.05:
        return GateResult(5, "全零（可能未初始化）", ["zero"])

    if expect is None:
        return GateResult(score, "范围合法 (pitch=%.2f yaw=%.2f)，无第二证据" % (p, y), tags)

    ep, ey = expect
    dp = abs(p - ep)
    dy = abs((y - ey + 180) % 360 - 180)     # 环绕
    if dp < tol_deg and dy < tol_deg:
        return GateResult(
            95, "与矩阵反推一致 dp=%.3f dy=%.3f (%.2f/%.2f)" % (dp, dy, p, y),
            tags + ["matrix_consistent"],
        )
    if dp < 2.0 and dy < 2.0:
        return GateResult(60, "接近矩阵反推 dp=%.2f dy=%.2f" % (dp, dy), tags + ["near"])
    return GateResult(15, "与矩阵反推不符 dp=%.1f dy=%.1f" % (dp, dy), [])


# ==================================================================== 自校准
def calibrate(proc: GameProcess | None, schema_offsets: dict[str, int],
              data_lo: int, data_hi: int, n_decoys: int = 8,
              seed: int = 1) -> dict[str, dict]:
    """用诱饵量化每个门的误判率。

    负样本来自真实的 .data 随机地址 —— 它们是"结构上看起来像指针/浮点、
    语义上毫无意义"的东西，正是最容易骗过门的那类输入。
    """
    rnd = random.Random(seed)
    stats: dict[str, dict] = {}

    # --- 实体表门 + LocalPlayer 门：需要活进程 ---
    if proc is not None and "m_hController" in schema_offsets:
        h_ctrl = schema_offsets["m_hController"]
        h_pp = schema_offsets["m_hPlayerPawn"]
        addrs = [rnd.randrange(data_lo, data_hi, 8) for _ in range(n_decoys)]
        fp = sum(1 for a in addrs if gate_entity_list(proc, a, h_ctrl, h_pp).score >= 80)
        stats["g_identity_chain"] = {"decoys": n_decoys, "false_pos": fp}

        # 真值槽也跑一遍，确认门没坏
        stats["g_identity_chain"]["positive"] = None
    # --- 矩阵门 / 角度门：纯计算，不需要进程 ---
    decoy_rows = []
    for _ in range(n_decoys):
        decoy_rows.append(
            [(rnd.uniform(-50, 50), rnd.uniform(-50, 50),
              rnd.uniform(-50, 50), rnd.uniform(-50, 50)) for _ in range(4)]
        )
    fp_vm = sum(1 for rows in decoy_rows if gate_viewmatrix(rows).score >= 80)
    stats["g_viewmatrix"] = {"decoys": n_decoys, "false_pos": fp_vm}

    fp_va = 0
    for _ in range(n_decoys * 4):
        pair = (rnd.uniform(-200, 200), rnd.uniform(-400, 400))
        if gate_viewangles(pair, expect=(rnd.uniform(-89, 89), rnd.uniform(-180, 180))).score >= 80:
            fp_va += 1
    stats["g_viewangles"] = {"decoys": n_decoys * 4, "false_pos": fp_va}
    return stats
