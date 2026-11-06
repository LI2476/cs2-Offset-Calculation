"""活体验证器：把 auto 解出的全部偏移拿到正在运行的游戏里逐条验。

**为什么需要这一步**：静态分析只能证明"这个名字在这个位置"，不能证明
"这个位置在运行时确实是那个语义"。唯一无争议的证据是活内存里读出合理的值。

判据分四类（强度递增）：
  1. 数值区间（血量 0~100）—— 弱，但能抓"整个错位"
  2. 交叉一致（m_angEyeAngles == dwViewAngles）—— 强，两个独立偏移互证
  3. 指针可解（指针落在堆区、能继续往下读）—— 强
  4. 句柄链闭合（句柄经实体表解出的对象，与另一条路径是同一个）—— 最强

用法：
    python verify_live.py --pid 16044
    python verify_live.py --pid 16044 --json _cache/live65.json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cs2re import auto, live, report, targets
from cs2re.live import GameProcess

# ---------------------------------------------------------------- 判据表
# kind 决定怎么验：
#   i32/u32/u8/u16/f32/u64 : 按类型读出来看区间
#   ptr                    : 必须是可读的堆指针
#   handle                 : 必须是能经实体表解出对象的句柄
#   angle                  : 必须与 dwViewAngles 一致
#   vec3                   : 三个 float 都有限且模长合理
#   bool                   : 0 或 1
#   eq                     : 与另一个字段相等
RULES: dict[str, dict] = {
    # ---- pawn 本体 ----
    "m_iHealth":            {"kind": "i32", "lo": 0, "hi": 100},
    "m_iMaxHealth":         {"kind": "i32", "lo": 1, "hi": 100},
    "m_lifeState":          {"kind": "u8",  "lo": 0, "hi": 2},
    "m_iTeamNum":           {"kind": "u8",  "lo": 0, "hi": 3},
    "m_ArmorValue":         {"kind": "i32", "lo": 0, "hi": 100},
    "m_fFlags":             {"kind": "u32", "lo": 0, "hi": 0x1FFFF},
    "m_vecVelocity":        {"kind": "vec3", "maxnorm": 4000},
    "m_vecViewOffset":      {"kind": "vec3", "maxnorm": 200},
    "m_angEyeAngles":       {"kind": "angle"},
    "m_iShotsFired":        {"kind": "i32", "lo": 0, "hi": 300},
    "m_bIsScoped":          {"kind": "bool"},
    "m_iIDEntIndex":        {"kind": "i32", "lo": -1, "hi": 0x7FFF},
    # ---- pawn 上的指针 ----
    "m_pGameSceneNode":     {"kind": "ptr"},
    "m_pWeaponServices":    {"kind": "ptr"},
    "m_pCameraServices":    {"kind": "ptr"},
    "m_pAimPunchServices":  {"kind": "ptr"},
    "m_pMovementServices":  {"kind": "ptr"},
    "m_pBulletServices":    {"kind": "ptr", "maybe_null": True},
    "m_pRenderComponent":   {"kind": "ptr"},
    "m_pObserverServices":  {"kind": "ptr", "maybe_null": True},
    "m_hController":        {"kind": "handle"},
    # ---- controller ----
    "m_hPlayerPawn":        {"kind": "handle"},
    "m_iPing":              {"kind": "i32", "lo": 0, "hi": 2000},
    "m_bPawnHasDefuser":    {"kind": "bool"},
    "m_bPawnHasHelmet":     {"kind": "bool"},
    "m_bIsPlayerNameDirty": {"kind": "bool"},
    "m_steamID":            {"kind": "u64", "min": 1},
    "m_iszPlayerName":      {"kind": "str"},
    "m_pActionTrackingServices": {"kind": "ptr"},
    "m_hObserverPawn":      {"kind": "handle", "maybe_null": True},
    # ---- 武器服务 ----
    "m_hMyWeapons":         {"kind": "handle_array"},
    "m_hActiveWeapon":      {"kind": "handle"},
    "m_hLastWeapon":        {"kind": "handle", "maybe_null": True},
    # ---- 武器 / item ----
    "m_iItemDefinitionIndex": {"kind": "u16", "lo": 0, "hi": 3000},
    "m_iEntityQuality":     {"kind": "i32", "lo": 0, "hi": 20},
    "m_AttributeManager":   {"kind": "embedded"},
    "m_bInitialized":       {"kind": "bool"},
    "m_bDisallowSOC":       {"kind": "bool"},
    "m_iItemIDHigh":        {"kind": "u32"},
    "m_iItemIDLow":         {"kind": "u32"},
    "m_iBurstShotsRemaining": {"kind": "i32", "lo": 0, "hi": 10},
    # ---- 相机服务 ----
    "m_iFOV":               {"kind": "i32", "lo": 0, "hi": 180},
    "m_iFOVStart":          {"kind": "i32", "lo": 0, "hi": 180},
    "m_flFOVTime":          {"kind": "f32", "lo": -1e9, "hi": 1e9},
    "m_flFOVRate":          {"kind": "f32", "lo": 0, "hi": 1e4},
    "m_vecCsViewPunchAngle": {"kind": "vec3", "maxnorm": 100},
    # ---- 后坐力服务 ----
    "m_predictableBaseAngle": {"kind": "vec3", "maxnorm": 100},
    # ---- 场景节点 ----
    "m_vecOrigin":          {"kind": "vec3", "maxnorm": 20000},
    "m_angAbsRotation":     {"kind": "vec3", "maxnorm": 720},
    # ---- 实体通用 ----
    "m_bSpotted":           {"kind": "bool"},
    "m_bSpottedByMask":     {"kind": "u32"},
    "m_hOwnerEntity":       {"kind": "handle", "maybe_null": True},
    "m_hGroundEntity":      {"kind": "handle", "maybe_null": True},
    # ---- 行动统计 ----
    "m_iNumRoundKills":     {"kind": "i32", "lo": 0, "hi": 20},
    "m_flTotalRoundDamageDealt": {"kind": "f32", "lo": 0, "hi": 2000},
    # ---- 观察者 ----
    "m_hObserverTarget":    {"kind": "handle", "maybe_null": True},
    # ---- C4（局外为 0，跳过）----
    "m_nBombSite":          {"kind": "i32", "lo": 0, "hi": 2, "c4": True},
    "m_flTimerLength":      {"kind": "f32", "lo": 0, "hi": 100, "c4": True},
}

# 这些字段的宿主不是 pawn，需要单独定位
HOST_OTHER = {
    "m_hPlayerPawn": "controller", "m_iPing": "controller",
    "m_bPawnHasDefuser": "controller", "m_bPawnHasHelmet": "controller",
    "m_bIsPlayerNameDirty": "controller", "m_steamID": "controller",
    "m_iszPlayerName": "controller", "m_pActionTrackingServices": "controller",
    "m_hObserverPawn": "controller",
    "m_hMyWeapons": "weaponServices", "m_hActiveWeapon": "weaponServices",
    "m_hLastWeapon": "weaponServices",
    "m_iItemDefinitionIndex": "weapon", "m_iEntityQuality": "weapon",
    "m_AttributeManager": "weapon", "m_bInitialized": "weapon",
    "m_bDisallowSOC": "weapon", "m_iItemIDHigh": "weapon",
    "m_iItemIDLow": "weapon", "m_iBurstShotsRemaining": "weapon",
    "m_iFOV": "cameraServices", "m_iFOVStart": "cameraServices",
    "m_flFOVTime": "cameraServices", "m_flFOVRate": "cameraServices",
    "m_vecCsViewPunchAngle": "cameraServices",
    "m_predictableBaseAngle": "aimPunch",
    "m_vecOrigin": "sceneNode", "m_angAbsRotation": "sceneNode",
    "m_iNumRoundKills": "actionTracking",
    "m_flTotalRoundDamageDealt": "actionTracking",
    "m_hObserverTarget": "observerServices",
    "m_nBombSite": "plantedC4", "m_flTimerLength": "plantedC4",
}

# 复合偏移：这些字段在 schema 里是**嵌套结构内**的偏移，不能直接加到武器
# 实体指针上。宿主给 wep 时，实际地址 = wep + COMPOSITE[key]。
#
# 例：m_iItemDefinitionIndex 属于 C_EconItemView，而 C_EconItemView 是
# C_AttributeContainer.m_Item（+0x50）内嵌的；C_AttributeContainer 又挂在
# C_EconEntity.m_AttributeManager（+0x1290）。
#   0x1290 + 0x50 + 0x1BA = 0x149A
# 活读验证：两把武器（defindex 59 刀 / 4 手雷）在 0x149A 都读出合理值，
# 而按 wep+0x1BA 读出来是 39327（垃圾）。
COMPOSITE: dict[str, int] = {
    "m_iItemDefinitionIndex": 0x149A,   # 0x1290 + 0x50 + 0x1BA
    "m_iEntityQuality":       0x149C,   # 0x1290 + 0x50 + 0x1BC
    "m_bInitialized":         0x12E0 + 0x1E8,
    "m_bDisallowSOC":         0x12E0 + 0x1E9,
    "m_iItemIDHigh":          0x12E0 + 0x1D0,
    "m_iItemIDLow":           0x12E0 + 0x1D4,
    "m_iBurstShotsRemaining": 0x1F24,   # 这个确实在 C_CSWeaponBase 顶层
}


def _heap(addr: int) -> bool:
    return 0x10000 < addr < 0x7FFF_FFFF_FFFF and (addr & 0x7) == 0


class Verifier:
    def __init__(self, proc: GameProcess):
        self.p = proc
        self.notes: list[str] = []

    def q(self, addr: int) -> int:
        raw = self.p.read(addr, 8)
        return struct.unpack("<Q", raw)[0] if raw and len(raw) == 8 else 0

    def u32(self, addr: int) -> int:
        raw = self.p.read(addr, 4)
        return struct.unpack("<I", raw)[0] if raw and len(raw) == 4 else -1

    def es_resolve(self, es: int, handle: int) -> int:
        """句柄 → 实体地址。

        链：es+0x10+8*(idx>>9) → chunk 数组 → chunk + 0x70*(idx&0x1FF)

        **必须先用 0x7FFF 掩码取出 index**，再 >>9 算 chunk。
        直接 handle>>9 是错的 —— 高 17 位是 serial（复用计数），
        混进去会把 chunk 号算成天文数字，全部解不出。
        真实踩过的坑：m_hController=0xD98001，直接 >>9 = 0x6CC0，
        而正确 index = 1，chunk = 0。
        """
        if not handle or not _heap(es):
            return 0
        if handle == 0xFFFFFFFF:      # INVALID_EHANDLE_INDEX
            return 0
        idx = handle & 0x7FFF
        chunk = self.q(es + 0x10 + 8 * (idx >> 9))
        if not _heap(chunk):
            return 0
        return self.q(chunk + 0x70 * (idx & 0x1FF))

    def check(self, name: str, off: int, host: int, host_name: str,
              es: int, global_angles, in_match: bool = True,
              has_weapon: bool = True) -> dict:
        rule = RULES.get(name)
        out = {"key": name, "host": host_name, "offset": off, "ok": None,
               "detail": ""}
        if rule is None:
            out["detail"] = "无判据（跳过）"
            return out

        # ---- 状态门：不在对局时，某些字段的判据不适用 ----
        # 实测过两次血案：主菜单/观战态跑验证，把这 4 条判成"失败"，
        # 看起来像偏移算错了，其实是**当前状态根本没有这个数据**：
        #   * m_angEyeAngles：不在对局时 pawn 停在最后一次复制的视线角，
        #     而 dwViewAngles 是实时客户端视角（自由视角可以随便转），
        #     两者天然不等（实测差 14.2°）——不是偏移错。
        #   * m_hMyWeapons / m_hActiveWeapon / m_hLastWeapon：手上没枪时
        #     m_hActiveWeapon = 0xFFFFFFFF、m_hMyWeapons 长度为 0，
        #     任何解句柄的动作都必然失败。
        # 状态门只挡住"没数据"，有数据时判据照旧严格。
        if not in_match:
            if rule.get("kind") == "angle":
                out["detail"] = "不在对局（队伍未分配），视线角不参与比对"
                return out
            # 武器三项：weaponServices 指针本身是有效的，但手上没枪。
            # 判据要看"有没有枪"，不是"服务对象在不在"。
            if host_name == "weapon" and not _heap(host):
                out["detail"] = "不在对局且无武器（当前武器为空），跳过"
                return out
            if host_name == "weaponServices" and rule.get("kind") in \
                    ("handle", "handle_array") and not has_weapon:
                out["detail"] = "不在对局且无武器（%s），跳过" % name
                return out
        if not host or not _heap(host):
            out["ok"] = None
            out["detail"] = "%s 不可用（宿主地址无效）" % host_name
            return out
        kind = rule["kind"]
        a = host + off

        if kind == "ptr":
            v = self.q(a)
            if v == 0 and rule.get("maybe_null"):
                out["ok"] = True
                out["detail"] = "空指针（此状态下允许）"
                return out
            readable = bool(self.p.read(v, 8)) if _heap(v) else False
            out["ok"] = bool(_heap(v) and readable)
            out["detail"] = "%#x %s" % (v, "可读" if out["ok"] else "不可读/非堆")
            return out

        if kind == "embedded":
            # 内嵌结构判据：C_AttributeContainer 只有 3 个字段
            # （+0x50 m_Item、+0x600、+0x608），所以"看几个指针像不像"
            # 这个判据是错的 —— 实测只有 1/5 命中，会被误判成错位。
            # 正确判据：它内嵌的 C_EconItemView 里能读出合理 defindex。
            di = struct.unpack("<H", self.p.read(a + 0x50 + 0x1BA, 2) or b"\xff\xff")[0]
            qu = self.u32(a + 0x50 + 0x1BC)
            out["ok"] = bool(0 <= di <= 1500 and 0 <= qu <= 20)
            out["detail"] = "内嵌 m_Item(+0x50) 的 defindex=%d quality=%d" % (di, qu)
            return out

        if kind == "handle":
            h = self.u32(a)
            # 0xFFFFFFFF 是引擎的 INVALID_EHANDLE_INDEX，表示"没有这个句柄"。
            # 它是**合法值**，不是错位证据 —— 实体没拥有者、没站地面时都写这个。
            if h in (0, 0xFFFFFFFF) and rule.get("maybe_null"):
                out["ok"] = True
                out["detail"] = ("空句柄" if h == 0 else "INVALID(0xFFFFFFFF)，此状态下合法")
                return out
            ent = self.es_resolve(es, h)
            out["ok"] = bool(ent)
            out["detail"] = "句柄 %#x → 实体 %#x" % (h, ent) if ent else \
                            "句柄 %#x 解不出实体" % h
            return out

        if kind == "handle_array":
            # m_hMyWeapons 是 CNetworkUtlVectorBase，+0x8 是数据指针
            ptr = self.q(a + 0x8)
            n = self.u32(a)
            good = 0
            if _heap(ptr) and 0 < n < 64:
                for i in range(min(n, 8)):
                    h = self.u32(ptr + 4 * i)
                    if self.es_resolve(es, h):
                        good += 1
            out["ok"] = good > 0
            out["detail"] = "长度 %d，前 %d 个句柄能解出 %d 个实体" % (
                n, min(n, 8), good)
            return out

        if kind == "angle":
            got = self.p.read(a, 8)
            if not got or len(got) != 8 or global_angles is None:
                out["ok"] = False
                out["detail"] = "读不到或没有对照值"
                return out
            p_, y_ = struct.unpack("<2f", got)
            gp, gy = global_angles
            dp = abs(p_ - gp)
            dy = abs((y_ - gy + 180) % 360 - 180)
            out["ok"] = dp < 0.5 and dy < 0.5
            out["detail"] = "(%+.3f, %+.3f) vs dwViewAngles (%+.3f, %+.3f) 差 %.4f/%.4f" % (
                p_, y_, gp, gy, dp, dy)
            return out

        if kind == "vec3":
            raw = self.p.read(a, 12)
            if not raw or len(raw) != 12:
                out["ok"] = False
                out["detail"] = "读不到"
                return out
            v = struct.unpack("<3f", raw)
            finite = all(x == x and abs(x) != float("inf") for x in v)
            norm = max(abs(x) for x in v) if finite else float("inf")
            out["ok"] = bool(finite and norm <= rule["maxnorm"])
            out["detail"] = "(%+.3f, %+.3f, %+.3f) 最大分量 %.1f ≤ %.1f" % (
                v[0], v[1], v[2], norm, rule["maxnorm"])
            return out

        if kind == "bool":
            b = self.p.read(a, 1)
            val = b[0] if b else -1
            out["ok"] = val in (0, 1)
            out["detail"] = "%d" % val
            return out

        if kind == "str":
            raw = self.p.read(a, 32)
            if not raw:
                out["ok"] = False
                out["detail"] = "读不到"
                return out
            s = raw.split(b"\x00")[0]
            try:
                txt = s.decode("utf-8")
            except UnicodeDecodeError:
                txt = ""
            out["ok"] = len(txt) >= 1 and all(32 <= ord(c) < 127 or ord(c) > 127
                                              for c in txt)
            out["detail"] = repr(txt[:28])
            return out

        # 数值类型
        size = {"i32": 4, "u32": 4, "u8": 1, "u16": 2, "u64": 8, "f32": 4}[kind]
        raw = self.p.read(a, size)
        if not raw or len(raw) != size:
            out["ok"] = False
            out["detail"] = "读不到"
            return out
        if kind == "i32":
            val = struct.unpack("<i", raw)[0]
        elif kind == "u32":
            val = struct.unpack("<I", raw)[0]
        elif kind == "u8":
            val = raw[0]
        elif kind == "u16":
            val = struct.unpack("<H", raw)[0]
        elif kind == "u64":
            val = struct.unpack("<Q", raw)[0]
        else:
            val = struct.unpack("<f", raw)[0]
        if "lo" in rule:
            out["ok"] = rule["lo"] <= val <= rule["hi"]
            out["detail"] = "%s ∈ [%s, %s]" % (
                ("%.4f" % val) if kind == "f32" else val, rule["lo"], rule["hi"])
        elif "min" in rule:
            out["ok"] = val >= rule["min"]
            out["detail"] = "%d ≥ %d" % (val, rule["min"])
        else:
            out["ok"] = True
            out["detail"] = str(val)
        return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="活体验证全部偏移")
    ap.add_argument("--pid", type=int, default=None,
                    help="cs2.exe 的 PID；不给就自动找（推荐）")
    ap.add_argument("--json", default=None)
    ap.add_argument("--dll", default=None)
    a = ap.parse_args(argv)

    # ---- 定进程 ----
    # 不给 --pid 就自动挑；给了也要核对（PID 会被系统复用，
    # 上次的 16044 这次可能是别的程序，连上去读出来全是垃圾）。
    try:
        info = live.pick_process("cs2", a.pid)
    except LookupError as exc:
        print("失败：%s" % exc, file=sys.stderr)
        return 3
    a.pid = info.pid

    img = auto.pe.Image(a.dll or auto.DEFAULT_DLL)
    proc = GameProcess(a.pid)
    v = Verifier(proc)

    print("=" * 70)
    print("活体验证（PID %d，%s）" % (a.pid, info.exe))
    print("=" * 70)

    # 活模块与磁盘 DLL 是否是同一个版本。
    # 不是的话 RVA 会整体错位 —— 那种情况下所有判据都会"失败"，
    # 但根因是版本不匹配，不是偏移错。先拦下来，免得看错方向。
    same, msg = proc.verify_against(a.dll or auto.DEFAULT_DLL)
    print("版本校验 %s" % msg)
    if not same:
        print("  ! 活进程里的 client.dll 与磁盘文件不是同一版本（游戏更新过但没重启？）")
        print("  ! 下面的结果不可信，先重启游戏再来。")
        proc.close()
        return 4
    print()

    # ---- 定位各宿主 ----
    # 注意：RVA 要加**活基址**（proc.base），不是 image_base。
    # 写成 proc.base - img.image_base + rva 会算出垃圾地址（真实踩过的坑：
    # 那一下 58 条全部"宿主地址无效"，看起来像工具坏了，其实是算式错）。
    pawn = v.q(proc.base + 0x2569948)
    ctrl = v.q(proc.base + 0x2541538)
    es = v.q(proc.base + 0x271EBA8)
    print("pawn       %#x" % pawn)
    print("controller %#x" % ctrl)
    print("entitySystem %#x" % es)

    global_angles = None
    ga = proc.read_rva(0x256F188, 8)
    if ga and len(ga) == 8:
        global_angles = struct.unpack("<2f", ga)

    hosts = {"pawn": pawn, "controller": ctrl}
    # 二级宿主
    svc = v.q(pawn + 0x12F0) if _heap(pawn) else 0
    cam = v.q(pawn + 0x1328) if _heap(pawn) else 0
    aim = v.q(pawn + 0x1598) if _heap(pawn) else 0
    scn = v.q(pawn + 0x330) if _heap(pawn) else 0
    obs = v.q(pawn + 0x1308) if _heap(pawn) else 0
    ats = v.q(ctrl + 0x828) if _heap(ctrl) else 0
    hosts.update({"weaponServices": svc, "cameraServices": cam,
                  "aimPunch": aim, "sceneNode": scn,
                  "observerServices": obs, "actionTracking": ats})
    # 当前武器
    wep = 0
    if _heap(svc):
        h = v.u32(svc + 0x60)
        wep = v.es_resolve(es, h)
    hosts["weapon"] = wep
    hosts["plantedC4"] = 0     # 局外/未安放时为 0

    # ---- 判断当前是否在对局、手上是否有枪 ----
    # CS2 的 m_iTeamNum：0 = 未分配、1 = 观战、2 = T、3 = CT。
    # **必须是 2/3 才算真的在局内**。写成 "in (0,1,2,3)" 是错的 ——
    # 主菜单和观战都读 0，那样状态门永远不触发（实测踩过：明明没进局，
    # 却报"对局中"，然后 4 条判据全炸）。
    in_match = False
    has_weapon = bool(_heap(wep))
    team = -1
    if _heap(ctrl):
        team = struct.unpack("<B", proc.read(ctrl + 0x3E7, 1))[0]
        in_match = team in (2, 3)
    print("状态       队伍=%d → %s" % (team, "对局中" if in_match else "不在对局"))
    print("手上武器   %s" % ("0x%x" % wep if has_weapon else "空手"))

    for k in ("pawn", "controller", "weaponServices", "cameraServices",
              "aimPunch", "sceneNode", "weapon", "observerServices",
              "actionTracking"):
        print("%-16s %#x" % (k, hosts[k]))

    # ---- 逐条验证 ----
    rows = []
    for name, (off, tag, desc) in targets.TIER_A.items():
        host_name = HOST_OTHER.get(name, "pawn")
        rule = RULES.get(name, {})
        if rule.get("c4") and not hosts.get("plantedC4"):
            rows.append({"key": name, "host": "plantedC4", "offset": off,
                         "ok": None, "detail": "局外无 C4，跳过"})
            continue
        host = hosts.get(host_name, 0)
        if host_name == "weapon" and name in COMPOSITE:
            off = COMPOSITE[name]
        rows.append(v.check(name, off, host, host_name, es, global_angles,
                            in_match=in_match, has_weapon=has_weapon))

    ok = sum(1 for r in rows if r["ok"] is True)
    bad = sum(1 for r in rows if r["ok"] is False)
    skip = sum(1 for r in rows if r["ok"] is None)
    for r in rows:
        mark = {True: " OK ", False: "  ×  ", None: " -  "}[r["ok"]]
        print("%s %-28s %-16s +%#-6x %s"
              % (mark, r["key"], r["host"], r["offset"], r["detail"]))
    print("\n合计 %d 条：通过 %d，失败 %d，跳过 %d" % (len(rows), ok, bad, skip))

    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(
            json.dumps({"pid": a.pid, "ok": ok, "bad": bad, "skip": skip,
                        "rows": rows}, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print("JSON → %s" % a.json)
    proc.close()
    return 0 if bad == 0 else 2


if __name__ == "__main__":
    # 和 verify_all39 一样：屏幕照打，同时落一份到 下载\cs2-re\。
    # 被 auto.py 当子进程调起时同样生效（它只取 returncode，不管输出）。
    if report.enabled():
        with report.capture("verify-live"):
            _rc = main()
        sys.exit(_rc)
    sys.exit(main())
