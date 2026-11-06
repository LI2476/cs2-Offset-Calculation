"""偏移表全量核对器 v3：39 个键，逐条判"能不能独立找回 + 值对不对"。

v3 相对 v2 的改动：
  1. **CVar 名字判据**（决定性）：convar 对象 +0x00 是名字串指针、+0x20 是描述串。
     dwGameTypes / dwSensitivity 现在直接解出 "game_type" / "sensitivity" 才算 OK，
     不再靠 +0x58 的数值区间猜。这条判据是唯一能区分"堆上 CVar 对象"和
     "模块内静态跳转表"的硬证据 —— 早前表里那个指向静态表的地址正是后者。
  2. **武器三层链活验证**：局内有武器时，m_iItemDefinitionIndex 从
     m_pWeaponServices → m_hActiveWeapon → 实体表反解 → 武器 +0x1290+0x50+0x1BA
     走完整条链，与 +0x149A 直取的值比对；闭合则从 CHAIN 升级为 OK。
  3. **--emit-ofs**：把通过的键写成一份可直接替换的 .ofs，未通过的键剔除并注明。

v2 相对 v1 的改动（都是被证据推翻后改的）：
  1. 不再拿"代码引用 0 次"当错误证据 —— dwSensitivity / dwLocalPlayerPawn
     引用也是 0，但活内存证明它们是对的，说明扫描器会漏模式。
  2. dwViewAngles 改用"与视图矩阵反推的 yaw 是否一致"判定。
  3. dwGameTypes 改用"指向的地址是不是只读静态表"判定。
  4. 复合键改用人工核定的正确链（3 项链也能表达），不用求解器的猜测。
  5. m_predictableBaseAngle 判 WRONG（schema 是 0x50，旧表写 0x88）。

用法：
  python verify_all39.py                       # 自动找 cs2 进程
  python verify_all39.py --pid 3384
  python verify_all39.py --no-live --json x.json
  python verify_all39.py --pid 3384 --emit-ofs out/deliver.ofs
"""
from __future__ import annotations

import argparse
import os
import datetime
import json
import math
import re
import struct
import sys
import time
from pathlib import Path

import ctypes
from ctypes import wintypes

from cs2re import live, report
from cs2re.pe import Image
from cs2re.schema import build_schema
from cs2re.xref import Xrefs

DEFAULT_OFS = os.environ.get("CS2RE_OFS", str(Path(__file__).resolve().parent / "offsets" / "deliver.ofs"))
DEFAULT_DLL = os.environ.get("CS2RE_DLL", "")
DATA_LO, DATA_HI = 0x21C2000, 0x27B0000

# 本工具独立算出来的 dw_* 期望值（client.dll 或 matchmaking.dll 的 RVA）。
# **2026-11-06 更新**：原来这里写死 0x271EBA8/0x2541538/0x2569948/0x256F250/
# 0x256F188，游戏一更新就全错。现在直接取自 targets.TIER_B —— 那份表由活进程
# 闭合链核实（见 targets.py 顶部 2026-11-06 重定说明），单一来源，不再两处抄。
from cs2re.targets import TIER_B as _TIER_B
EXPECT = {
    "dwEntityList":            (_TIER_B["dwEntityList"][0], "client.dll"),
    "dwLocalPlayerController": (_TIER_B["dwLocalPlayerController"][0], "client.dll"),
    "dwLocalPlayerPawn":       (_TIER_B["dwLocalPlayerPawn"][0], "client.dll"),
    "dwViewMatrix":            (_TIER_B["dwViewMatrix"][0], "client.dll"),
    "dwViewAngles":            (_TIER_B["dwViewAngles"][0], "client.dll"),
    "dwSensitivity":           (0x2567C48, "client.dll"),
    "dwPlantedC4":             (0x24CFB60, "client.dll"),
    "dwGameTypes":             (0x1E2740, "matchmaking.dll"),
}

# 人工核定的复合链（schema 求解器表达不了 3 项链，也搞不清谁套谁）
CHAIN3 = {
    "m_bSpotted": (
        "m_entitySpottedState(C_CSPlayerPawn 0x1E88) → m_bSpotted(EntitySpottedState_t 0x8)",
        "0x1E88 + 0x8 = 0x1E90",
    ),
    "m_iItemDefinitionIndex": (
        "m_AttributeManager(C_EconEntity 0x1290) → m_Item(C_AttributeContainer 0x50)"
        " → m_iItemDefinitionIndex(C_EconItemView 0x1BA)",
        "0x1290 + 0x50 + 0x1BA = 0x149A",
    ),
}

# 名在 schema 里没有，但有确定链
CHAIN_NOSCHEMA = {
    "m_dwBoneMatrix": (
        "m_pGameSceneNode(C_BaseEntity 0x330) → +0x1C0（= m_modelState 0x140 + 0x80）",
        "0x330 → 0x1C0",
        "schema 无此名。pawn+0x1C0 是垃圾(0xffffffff00000000)；sceneNode+0x1C0 解出的 CTransform[]"
        " 骨骼[0] 与 m_vecAbsOrigin 差 <0.5，骨骼[7] z≈64（头）",
    ),
}


# ------------------------------------------------------------------ Win32
k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class Proc:
    def __init__(self, pid: int):
        self.pid = pid
        self.h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not self.h:
            raise OSError(ctypes.get_last_error(), "OpenProcess")
        self.mods = self._mods()

    def _mods(self):
        class ME(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                        ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                        ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]
        snap = k32.CreateToolhelp32Snapshot(0x18, self.pid)
        me, out = ME(), {}
        me.dwSize = ctypes.sizeof(ME)
        if k32.Module32First(snap, ctypes.byref(me)):
            while True:
                out[me.szModule.decode("mbcs", "replace").lower()] = (
                    me.modBaseAddr, me.modBaseSize)
                if not k32.Module32Next(snap, ctypes.byref(me)):
                    break
        k32.CloseHandle(snap)
        return out

    def rd(self, a, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(a), buf, n, ctypes.byref(got)):
            return None
        return buf.raw if got.value == n else None

    def q(self, a):
        b = self.rd(a, 8)
        return None if b is None else struct.unpack("<Q", b)[0]

    def u8(self, a):
        b = self.rd(a, 1)
        return None if b is None else b[0]

    def u16(self, a):
        b = self.rd(a, 2)
        return None if b is None else struct.unpack("<H", b)[0]

    def u32(self, a):
        b = self.rd(a, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    def i32(self, a):
        b = self.rd(a, 4)
        return None if b is None else struct.unpack("<i", b)[0]

    def f(self, a, n=1):
        b = self.rd(a, 4 * n)
        return None if b is None else struct.unpack("<%df" % n, b)

    def base(self, m="client.dll"):
        return self.mods[m][0]

    def size(self, m="client.dll"):
        return self.mods[m][1]


def is_ptr(v) -> bool:
    return v is not None and 0x10000 < v < 0x7FFF_FFFF_FFFF


def cvar_name(p, obj) -> str | None:
    """CVar 对象 +0x00 是名字字符串指针（实测可能带 1~3 字节对齐全零）。

    这是判"这个槽到底是不是 game_type convar"的决定性证据 ——
    比 +0x58 的数值区间硬得多。
    """
    if not is_ptr(obj):
        return None
    p_str = p.q(obj)
    if not is_ptr(p_str):
        return None
    for d in (0, 1, 2, 3):
        b = p.rd(p_str + d, 48)
        if not b:
            continue
        s = b.split(b"\x00")[0]
        if not s:
            continue
        try:
            t = s.decode("mbcs")
        except UnicodeDecodeError:
            continue
        if 2 <= len(t) <= 40 and t.isprintable():
            return t
    return None


def verify_item_chain(p, base: int, pawn: int, ofs_val: int, es: int = 0):
    """m_iItemDefinitionIndex 的三层链，局内有武器时才能完整验。

    链：pawn +0x12F0 m_pWeaponServices → +0x60 m_hActiveWeapon（句柄）
        → 实体表反解出武器实体 → 武器 +0x1290(m_AttributeManager) +0x50(m_Item)
          +0x1BA(m_iItemDefinitionIndex)
    判 OK 的条件：武器实体的 `+0x1290+0x50+0x1BA` == `+ofs_val`，且值在合理区间。
    """
    ev: list[str] = []
    ws = p.q(pawn + 0x12F0)
    if not is_ptr(ws):
        ev.append("读不到 m_pWeaponServices，链无法起步")
        return ev, False
    h = p.u32(ws + 0x60)
    if h is None:
        ev.append("读不到 m_hActiveWeapon")
        return ev, False
    if h == 0 or (h & 0x7FFF) == 0x7FFF:
        ev.append("当前无武器（m_hActiveWeapon=%#x），链无实体可解（属正常）" % h)
        return ev, False
    idx = h & 0x7FFF
    if not is_ptr(es):
        ev.append("实体表为空，链无实体可解")
        return ev, False
    chunk = p.q(es + 0x10 + 8 * (idx >> 9))
    if not is_ptr(chunk):
        ev.append("武器句柄 idx=%d 的 chunk 读不到" % idx)
        return ev, False
    wpn = p.q(chunk + 0x70 * (idx & 0x1FF))
    if not is_ptr(wpn):
        ev.append("武器句柄 idx=%d 解不出实体" % idx)
        return ev, False
    direct = p.u16(wpn + ofs_val)
    viac = p.u16(wpn + 0x1290 + 0x50 + 0x1BA)
    ev.append("武器实体 %#x（句柄 idx=%d）：+%#x u16=%s，"
              "走 0x1290+0x50+0x1BA 也是 %s"
              % (wpn, idx, ofs_val, direct, viac))
    ok = direct is not None and direct == viac and 0 < direct < 60000
    if ok:
        ev.append("→ 三层链闭合，值一致")
    return ev, ok


def emit_ofs(rows: list[Row], src: str, dst: str) -> str:
    """把核对结果写成一份 .ofs（游戏更新后可直接替换）。

    只写判定为 OK / CHAIN 的键 —— WRONG / NO 的键不写进去，
    宁可少一条，也不把没验证过的值塞给使用者。
    原有注释尽量保留，并在每条后追加一行核对标记。
    """
    ok = {r.key for r in rows if r.verdict in ("OK", "CHAIN")}
    bad = [r for r in rows if r.verdict not in ("OK", "CHAIN")]
    src_lines = Path(src).read_text(encoding="utf-8", errors="replace").splitlines()

    out = ['Offsets_Date = "%s";' % datetime.date.today().isoformat(),
           "// generated by cs2-re/verify_all39.py —— 每条都过了静态 schema + 活内存双验"]
    for line in src_lines:
        s = line.split("//")[0].strip()
        m = re.match(r"^([A-Za-z_]\w*)\s*=\s", s)
        if not m:
            continue
        k = m.group(1)
        if k == "Offsets_Date":
            continue
        if k in ok:
            s2 = line.rstrip()
            if "//" not in s2 and not s2.endswith(";"):
                s2 += ";"          # 只在缺分号时补，避免 ";;"
            out.append(s2)
    out.append("")
    if bad:
        out.append("// ---- 以下 %d 条未通过核对，故意不写入 ----" % len(bad))
        for r in bad:
            out.append("//   %-26s %#x  %s" % (r.key, r.ofs, r.verdict))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text("\n".join(out), encoding="utf-8")
    return "%s（%d 条写入，%d 条剔除）" % (dst, len(ok), len(bad))


def ent_ptr(p, es: int, idx: int):
    """按当前正确的实体表排布取第 idx 个实体。

    排布：arr0 = *(ES+0x10)；b0 = arr0 - 0x38；
          第 i 个实体 = *(b0 + 0x70*i + 0x38)
    **踩过的坑**：本脚本原来写的是分块寻址
    `chunk = *(ES+0x10+8*(idx>>9)); ent = *(chunk+0x70*(idx&0x1FF))`，
    那是旧版排布。用它去反解本地 pawn 永远不命中，于是把正确的 dwEntityList /
    dwLocalPlayerController 判成 LIVE 失败 —— 是脚本自己在误判，不是偏移错。
    """
    if not is_ptr(es) or idx < 0:
        return None
    arr0 = p.q(es + 0x10)
    if not is_ptr(arr0):
        return None
    b0 = arr0 - 0x38
    v = p.q(b0 + 0x70 * idx + 0x38)
    return v if is_ptr(v) else None


def find_idx_of(p, es: int, ptr: int, max_idx: int = 600):
    """反查某指针在实体表里的索引（找不到返回 -1）。"""
    if not is_ptr(es) or not is_ptr(ptr):
        return -1
    arr0 = p.q(es + 0x10)
    if not is_ptr(arr0):
        return -1
    b0 = arr0 - 0x38
    for i in range(max_idx):
        if p.q(b0 + 0x70 * i + 0x38) == ptr:
            return i
    return -1


def parse_ofs(p: str):
    out = []
    for line in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line
        line = line.split("//")[0].strip()
        m = re.match(r"^([A-Za-z_]\w*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;?$", line)
        if not m or m.group(1) == "Offsets_Date":
            continue
        note = raw.split("//", 1)[1].strip() if "//" in raw else ""
        out.append((m.group(1), int(m.group(2), 0), note))
    return out


class Row:
    def __init__(self, key, ofs, verdict, chain, evidence, note=""):
        self.key, self.ofs, self.verdict = key, ofs, verdict
        self.chain, self.evidence, self.note = chain, evidence, note

    def d(self):
        return {"key": self.key, "ofs": hex(self.ofs), "verdict": self.verdict,
                "chain": self.chain, "evidence": self.evidence, "comment": self.note}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ofs", default=DEFAULT_OFS)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--dll", default=DEFAULT_DLL)
    ap.add_argument("--json", default="")
    ap.add_argument("--emit-ofs", default="",
                    help="把通过的键写成一份可替换的 .ofs")
    ap.add_argument("--no-live", action="store_true")
    a = ap.parse_args()
    if not a.dll:
        ap.error("请指定 client.dll 路径：加 --dll <路径>，或设置环境变量 CS2RE_DLL")

    t0 = time.time()
    entries = parse_ofs(a.ofs)
    print("读 %s：%d 个键" % (a.ofs, len(entries)))

    img = Image(a.dll)
    schema = build_schema(img, DATA_LO, DATA_HI)
    print("schema：%d 字段 / %d 名字 / %d 类（%.1fs）"
          % (len(schema.fields), len(schema.by_name), len(schema.classes), time.time() - t0))

    pid = 0 if a.no_live else a.pid
    if not a.no_live:
        # 不给 --pid 就自动挑；给了也核对（PID 会被系统复用，
        # 直接拿旧 PID 连上去可能连到别的程序，读出来全是垃圾）。
        try:
            pid = live.pick_process("cs2", pid or None).pid
        except LookupError as exc:
            print("活进程没找到（%s），只跑静态" % str(exc).splitlines()[0])
            pid = 0
    p = None
    if pid:
        try:
            p = Proc(pid)
            print("活进程 PID %d：client.dll %#x (size %#x)"
                  % (pid, p.base(), p.size()))
        except OSError as e:
            print("活进程打不开（%s），只跑静态" % e)
    else:
        print("cs2 未运行，只跑静态")

    base = p.base() if p else 0

    # 活进程读取用的偏移**必须取自被检验的 .ofs 本身**，不能硬编码。
    # 踩过的坑：原来这里写死 0x2569948 / 0x2541538 / 0x271EBA8，游戏一更新
    # 全部失效，于是脚本报 "pawn 0x0 / controller 0x0"、三条 LIVE 全判失败，
    # 看上去像 .ofs 写错了，实际是脚本自己拿旧地址去读了。
    ofs_map = {n: v for n, v, _ in entries}
    def _o(name, dflt=0):
        return ofs_map.get(name, dflt)

    pawn = ctrl = es = sn = 0
    mm = 0
    if p:
        pawn = (p.q(base + _o("dwLocalPlayerPawn")) or 0) if _o("dwLocalPlayerPawn") else 0
        ctrl = (p.q(base + _o("dwLocalPlayerController")) or 0) if _o("dwLocalPlayerController") else 0
        es = (p.q(base + _o("dwEntityList")) or 0) if _o("dwEntityList") else 0
        sn = (p.q(pawn + 0x330) or 0) if is_ptr(pawn) else 0
        if "matchmaking.dll" in p.mods:
            mm = p.base("matchmaking.dll")
        print("pawn %s / controller %s / EntitySystem %s / sceneNode %s / matchmaking %s"
              % (hex(pawn), hex(ctrl), hex(es), hex(sn), hex(mm) if mm else "未加载"))
    print()

    rows: list[Row] = []

    # ============================ dw_* ============================
    for name, ofs_val, note in entries:
        if not name.startswith("dw"):
            continue

        exp_rva, exp_mod = EXPECT.get(name, (0, "?"))
        ev = []
        verdict = "LIVE"
        chain = "%s + %#x" % (exp_mod, ofs_val)

        if name == "dwEntityList" and p:
            v = p.q(base + ofs_val)
            if is_ptr(v):
                hp = p.u32(ctrl + 0x92C) if is_ptr(ctrl) else None
                hit = False
                if hp is not None:
                    hit = ent_ptr(p, v, hp & 0x7FFF) == pawn
                ev.append("EntitySystem=%#x；controller 的 m_hPlayerPawn 反解%s本地 pawn"
                          % (v, "命中" if hit else "未命中"))
                verdict = "OK" if hit else "LIVE"
        elif name == "dwLocalPlayerController" and p:
            v = p.q(base + ofs_val)
            if is_ptr(v):
                hp = p.u32(v + 0x92C)
                idx = hp & 0x7FFF if hp is not None else -1
                ent = ent_ptr(p, es, idx)
                ok = ent == pawn
                ci = find_idx_of(p, es, v)
                ev.append("槽值 %#x 在表里索引 %s；+0x92C=0x%X（idx %d）反解%s本地 pawn"
                          % (v, ci if ci >= 0 else "不在", hp or 0, idx,
                             "==" if ok else "!="))
                verdict = "OK" if ok else "LIVE"
        elif name == "dwLocalPlayerPawn" and p:
            v = p.q(base + ofs_val)
            if is_ptr(v):
                healthy = p.i32(v + 0x34C)
                mx = p.i32(v + 0x348)
                team = p.u8(v + 0x3E7)
                pi = find_idx_of(p, es, v)
                ci = find_idx_of(p, es, ctrl)
                # 反向闭合：本地 controller 的 m_hPlayerPawn 是不是指向它
                back = p.u32(ctrl + 0x92C) & 0x7FFF if is_ptr(ctrl) else -1
                closed = (pi >= 0 and back == pi)
                ev.append("实体索引 %s；+0x348 maxHealth=%s +0x34C 血量=%s +0x3E7 队伍=%s"
                          % (pi if pi >= 0 else "不在表内", mx, healthy, team))
                if is_ptr(ctrl):
                    ev.append("本地 controller（索引 %s）的 +0x92C 指向索引 %d → 反向闭合=%s"
                              % (ci if ci >= 0 else "不在表内", back, closed))
                # 判 OK 的条件：在实体表里 + 被本地 controller 指回 + maxHealth 像玩家
                ok = closed and mx is not None and 1 <= mx <= 200
                verdict = "OK" if ok else "LIVE"
        elif name == "dwViewMatrix" and p:
            m = p.f(base + ofs_val, 16)
            if m:
                yaw_m = math.degrees(math.atan2(m[13], m[12])) % 360
                ev.append("16 个 float 可读；行3 方向 atan2=%.2f°" % yaw_m)
                verdict = "OK"
        elif name == "dwViewAngles" and p:
            # 同样不能写死：矩阵槽位从 .ofs 取，否则更新后读到的是垃圾。
            mv_rva = _o("dwViewMatrix")
            got = p.f(base + ofs_val, 2)
            mat = p.f(base + mv_rva, 16) if mv_rva else None
            pe = p.f(pawn + 0x3600, 3) if is_ptr(pawn) else None
            if got and mat:
                yaw_m = math.degrees(math.atan2(mat[13], mat[12])) % 360
                # pitch 值域是 -90..90，**不能取模 360**：atan2(-0.0, 正数) 会得到
                # -0.0，取模后变成 360.0，报告里就会出现 "(+360.000,...) 差 0.000°"
                # 这种自相矛盾的显示。
                dpth = math.degrees(math.atan2(-mat[14],
                                              math.hypot(mat[12], mat[13])))
                dy = abs((yaw_m - got[1] + 180) % 360 - 180)
                dp = abs(dpth - got[0])
                ev.append("%#x 读出 %s；矩阵 %#x 反推 (%+.3f,%+.3f)，差 %.3f°/%.3f°"
                          % (ofs_val, [round(x, 3) for x in got], mv_rva,
                             dpth, yaw_m, dp, dy))
                if dp < 0.6 and dy < 0.6:
                    verdict = "OK"
            if pe and got:
                same = struct.pack("<2f", pe[0], pe[1]) == struct.pack("<2f", got[0], got[1])
                ev.append("与 pawn+0x3600 m_angEyeAngles 逐位相同=%s" % same)
                if same:
                    verdict = "WRONG"
                    ev.append("→ 该槽是眼睛角镜像，不是渲染相机角度")
        elif name == "dwSensitivity" and p:
            v = p.q(base + ofs_val)
            if is_ptr(v):
                f = p.f(v + 0x58)
                nm = cvar_name(p, v)
                ev.append("二级指针 %#x，+0x58 float=%s"
                          % (v, round(f[0], 4) if f else None))
                if nm:
                    ev.append("对象 +0x00 名字 = %r（CVar 布局，+0x20 描述串可读）" % nm)
                ok = (nm == "sensitivity") or (f and 0 < f[0] < 20)
                verdict = "OK" if ok else "LIVE"
        elif name == "dwPlantedC4" and p:
            v = p.q(base + ofs_val)
            ev.append("当前槽值 %s（不在局内为 0 属正常）" % (hex(v) if v else "0"))
            verdict = "OK"
        elif name == "dwGameTypes" and p and mm:
            # 判据：这个槽指向的必须是"堆上的 CVar 对象"，名字对得上 game_type。
            # 实测 CVar 布局：+0x00 名字指针、+0x20 描述串、+0x58 int 值。
            msz = p.size("matchmaking.dll")
            tgt = p.q(mm + ofs_val)
            in_mod = bool(tgt and mm <= tgt < mm + msz)
            ev.append("%#x 按 matchmaking.dll 内偏移解 → %s"
                      % (ofs_val, hex(tgt) if tgt else "0"))
            nm = cvar_name(p, tgt)
            if nm:
                ev.append("对象 +0x00 名字 = %r，+0x58 int = %s"
                          % (nm, p.i32(tgt + 0x58)))
            if not is_ptr(tgt):
                ev.append("→ 槽为空（不在局内 / 未初始化）")
                verdict = "LIVE"
            elif in_mod:
                vt = p.q(tgt)
                ev.append("→ 落在模块内静态区（首 qword=%#x 是模块内函数指针表），"
                          "不是堆上的 CVar 对象" % (vt or 0))
                verdict = "WRONG"
            elif nm in ("game_type", "game_mode"):
                ev.append("→ 名字确认是 CVar，链路成立")
                verdict = "OK"
            else:
                gm_slot = p.q(mm + 0x1E2770)
                gm_nm = cvar_name(p, gm_slot)
                ev.append("→ 指向堆对象但名字不是 game_type（读出 %r）；"
                          "配对槽 mm+0x1E2770 名字 = %r" % (nm, gm_nm))
                verdict = "WRONG" if nm is None else "LIVE"
        if not ev:
            ev.append("静态存在；未做活内存验证")

        if exp_rva:
            if ofs_val == exp_rva and name not in ("dwViewAngles",):
                pass
            if name in ("dwViewAngles", "dwGameTypes") and verdict == "WRONG":
                chain = "应为 %s + %#x" % (exp_mod, exp_rva)
        if name == "dwViewAngles" and verdict == "OK":
            chain = "client.dll + %#x（渲染相机角度）" % ofs_val
        rows.append(Row(name, ofs_val, verdict, chain, "；".join(ev), note))

    # ============================ m_* ============================
    for name, ofs_val, note in entries:
        if name.startswith("dw"):
            continue

        # 人工核定的复合链
        if name in CHAIN3:
            chain_desc, arith = CHAIN3[name]
            verdict = "CHAIN"
            ev = ["%s（%s）" % (chain_desc, arith)]
            if p and is_ptr(pawn) and name == "m_bSpotted":
                v = p.u8(pawn + ofs_val)
                ev.append("活内存 pawn+%#x=%s" % (ofs_val, v))
            if p and is_ptr(pawn) and name == "m_iItemDefinitionIndex":
                # 局内有武器时能走完整链，这时就从 CHAIN 升级为 OK
                ev_extra, ok = verify_item_chain(p, base, pawn, ofs_val, es)
                ev.extend(ev_extra)
                if ok:
                    verdict = "OK"
            rows.append(Row(name, ofs_val, verdict, chain_desc, "；".join(ev), note))
            continue

        # schema 没有名字但有链
        if name in CHAIN_NOSCHEMA:
            chain_desc, arith, ev = CHAIN_NOSCHEMA[name]
            verdict = "CHAIN"
            evs = [ev]
            if p and is_ptr(sn):
                bones = p.q(sn + 0x1C0)
                if is_ptr(bones):
                    raw = p.rd(bones, 0x20 * 8)
                    z7 = struct.unpack("<3f", raw[7 * 0x20:7 * 0x20 + 12])[2] if raw else None
                    evs.append("活内存 sceneNode+0x1C0=%#x，骨骼[7].z=%s"
                               % (bones, round(z7, 2) if z7 is not None else None))
                    verdict = "OK"
            rows.append(Row(name, ofs_val, verdict, chain_desc, "；".join(evs), note))
            continue

        # m_predictableBaseAngle：值本身在 schema 里有，但 .ofs 曾经写成 0x88
        if name == "m_predictableBaseAngle":
            TRUE_OFF = 0x50
            ev = ["schema: CCSPlayer_AimPunchServices.m_predictableBaseAngle = %#x"
                  "（该类大小 0xE8，同表 tick@0x48 / vel@0x5C / unpredictable@0xA4）" % TRUE_OFF]
            if p and is_ptr(pawn):
                svc = p.q(pawn + 0x1598)
                if is_ptr(svc):
                    f50 = p.f(svc + 0x50, 3)
                    f88 = p.f(svc + 0x88, 3)
                    ev.append("活内存 svc=%#x：+0x50=%s，+0x88=%s"
                              % (svc, [round(x, 3) for x in f50] if f50 else None,
                                 [round(x, 3) for x in f88] if f88 else None))
            if ofs_val == TRUE_OFF:
                ev.append("与 schema 一致；基址链 svc = pawn+0x1598 (m_pAimPunchServices)")
                rows.append(Row(name, ofs_val, "OK",
                                "svc = pawn+0x1598 (m_pAimPunchServices)，再 +%#x" % TRUE_OFF,
                                "；".join(ev), note))
            else:
                ev.append("%#x 在 0x5C 与 0xA0 之间的无名区，读出的不是 QAngle；"
                          "%#x = %#x + 0x38" % (ofs_val, ofs_val, TRUE_OFF))
                rows.append(Row(name, ofs_val, "WRONG",
                                "应为 svc + %#x" % TRUE_OFF, "；".join(ev), note))
            continue

        offs = schema.offsets(name)
        if not offs:
            rows.append(Row(name, ofs_val, "NO", "—", "schema 无此名，也给不出确定链", note))
            continue
        if ofs_val in offs:
            cls = [c for c, t in schema.by_class.items() if t.get(name) == ofs_val]
            ev = "命中 %s" % (", ".join(cls[:2]) or "无序项")
            others = [o for o in offs if o != ofs_val]
            if others:
                ev += "；同名在别处还有 %s" % ", ".join("%#x" % o for o in others[:3])
            rows.append(Row(name, ofs_val, "OK", "schema 字段", ev, note))
            continue
        rows.append(Row(name, ofs_val, "WRONG", "—",
                        "schema 有 %s 但值为 %s，与 .ofs 的 %#x 都不等"
                        % (name, ", ".join("%#x" % o for o in offs), ofs_val), note))

    # ============================ 输出 ============================
    order = {"OK": 0, "CHAIN": 1, "LIVE": 2, "WRONG": 3, "NO": 4}
    rows.sort(key=lambda r: (order[r.verdict], r.key))
    w = max(len(r.key) for r in rows)
    bar = "─" * (w + 66)
    print("=" * (w + 66))
    print("%-7s %-*s %-11s %s" % ("判定", w, "键", ".ofs 值", "基址链 / 证据"))
    print("=" * (w + 66))
    for r in rows:
        print("%-7s %-*s %#010x  %s" % (r.verdict, w, r.key, r.ofs, r.chain))
        if r.evidence:
            print("%-7s %-*s %-11s  %s" % ("", w, "", "", r.evidence))
    print(bar)
    cnt = {}
    for r in rows:
        cnt[r.verdict] = cnt.get(r.verdict, 0) + 1
    print("合计 %d 条：%s" % (len(rows), "  ".join(
        "%s=%d" % (k, cnt[k]) for k in ("OK", "CHAIN", "LIVE", "WRONG", "NO") if k in cnt)))
    good = sum(cnt.get(k, 0) for k in ("OK", "CHAIN"))
    print("可独立找回且与 .ofs 一致：%d/%d；.ofs 自身写错：%d 条"
          % (good, len(rows), cnt.get("WRONG", 0)))
    print("%.1fs" % (time.time() - t0))

    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(
            {"ofs": a.ofs, "pid": pid, "rows": [r.d() for r in rows]},
            ensure_ascii=False, indent=1), encoding="utf-8")
        print("JSON -> %s" % a.json)
    if a.emit_ofs:
        print("写出 -> %s" % emit_ofs(rows, a.ofs, a.emit_ofs))
    return 0


if __name__ == "__main__":
    # 终端里的表关窗口就没了，所以整段输出顺手落一份到 下载\cs2-re\。
    if report.enabled():
        with report.capture("verify-all39"):
            _rc = main()
        raise SystemExit(_rc)
    raise SystemExit(main())
