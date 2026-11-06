"""CS2 offsets — 本机实测（2026-11-04，build 见 state.json）。

全部条目都用活进程验证过：读到的值与游戏内可见状态一致。
用法：import offsets; 先 offsets.bind(cs2) 再访问。

注意：所有偏移都是 client.dll 内的相对偏移（RVA）或实体/对象内偏移，
换局、换号、重启后依然成立；只有模块基址每次启动要重新取。
"""

# ============ 一、client.dll 内的全局槽位（client.dll + RVA） ============
GLOBAL = {
    # 实体系统根：CGameEntitySystem*
    "dwEntityList": 0x23BFA10,
    # 视图矩阵：float[4][4]，首个矩阵；函数 0xC15A23 里就是 &m[0] + idx*64
    "dwViewMatrix": 0x256F250,
    # 本机 controller 静态槽（值是 CCSPlayerController*）
    "dwLocalPlayerController": 0x21D6F50,
    # 本机 pawn 静态槽（值是 C_CSPlayerPawn*，与 controller 不同源）
    "dwLocalPlayerPawn": 0x2569948,
    # 视角角数组基址：float[3] (pitch, yaw, roll)，步长 8 字节按槽位索引（分屏）。
    # 依据：矩阵 0x256F250 的访问器函数（lea rcx,[rip+matrix]; ...lea rax,[rax+rcx*4]）
    # 与 0x256F188 的访问器（0xc14980，步长 8）同函数簇；矩阵反推 yaw 与此处
    # yaw 吻合到 0.000004 度（2026-11-04 实测）。
    "dwViewAngles": 0x256F188,
}

# ============ 二、句柄解码 ============
# 实体句柄（uint32）低 15 位 = 实体索引；索引 -> CEntityIdentity -> 实例
HANDLE_INDEX_MASK = 0x7FFF

# ============ 三、CEntityIdentity / 实体列表结构 ============
IDENTITY = {
    "chunk_shift": 9,        # idx >> 9 选 chunk
    "per_chunk": 512,        # idx & 511 选块内序号
    "stride": 0x70,          # 每个 identity 占 0x70
    "instance": 0x38,        # identity + 0x38 = 游戏对象指针
    "base_delta": 0x38,      # B0 = *(ES+0x10) - 0x38（本机实测的排布）
}

# ============ 四、pawn（C_CSPlayerPawn）内偏移 ============
PAWN = {
    # ---- 基础状态 ----
    "m_iHealth": 0x34C,          # int，实测 100
    "m_iMaxHealth": 0x348,       # int，实测 100
    "m_lifeState": 0x354,        # int，存活=0/其它=非 0
    "m_iTeamNum": 0x3E7,         # uint8，T=2 CT=3
    "m_ArmorValue": 0x1ED0,      # int 护甲
    "m_bDormant": 0x103,         # bool 休眠
    # ---- 位置 / 视角 ----
    "m_vecAbsOrigin": 0xC8,      # vec3 世界坐标（经 scene node，实测准）
    "m_angEyeAngles": 0x3600,    # vec2/vec3 视线角（pitch, yaw），实测 -5.0/-77.8
    "m_vecViewOffset": 0xF60,    # vec3 眼高偏移，实测 z=63.7
    "m_iShotsFired": 0x1EB8,     # int 连发计数
    # ---- 组件指针 ----
    "m_pWeaponServices": 0x12F0,
    "m_pCameraServices": 0x1328,
    "m_pAimPunchServices": 0x1598,
    "m_pMovementServices": 0x1330,
    "m_pBulletServices": 0x1570,
    "m_pRenderComponent": 0x338,
    # ---- 骨骼 ----
    "m_pSceneNode": 0x330,       # -> CGameSceneNode（也是 skeleton 实例指针）
    # ---- 归属 ----
    "m_hController": 0x14BC,     # 所属 controller 句柄
}

# ============ 五、scene node / 骨骼链 ============
SCENE_NODE = {
    "m_vecAbsOrigin": 0xC8,   # 与 pawn+0xC8 同值（实测）
    "m_vecOrigin": 0x80,      # 局部坐标
    "m_angAbsRotation": 0xD4,
    "bone_array_rel": 0x378,  # scene_node + 0x378 = modelState 指针（实测与 0x388 同值）
}
MODEL_STATE = {
    "m_pBoneArray": 0x80,     # modelState + 0x80 = CTransform[ ] 指针
}
BONE = {
    "stride": 32,             # 每个骨骼 32 字节：vec3 pos(12) + float(4) + quat4(16)
    "pos": 0x00,
    "quat": 0x10,
    "count_human": 110,       # 人类模型有效根数（不同 agent 模型 100~112 不等）
    "feet": 0,                # 恒等于 footprint 原点 (0,0,0)
    "pelvis": 0xC,            # 骨盆区
    "head": 7,                # 实测：z 最高且距眼睛最近（d≈4cm）
    "head_alt": 6,            # 次选（部分模型两者几乎重合）
    "neck": 25,
}

# ============ 六、武器链 ============
WEAPON_SERVICES = {
    "m_hMyWeapons": 0x48,        # CNetworkUtlVectorBase<CHandle<C_BasePlayerWeapon>>
    "m_hActiveWeapon": 0x60,     # 当前武器句柄（实测 0x2F00FB -> idx 251）
    "m_hLastWeapon": 0x64,
    "m_iAmmo": 0x68,             # 本版本留空，弹药改在武器实体里
}
WEAPON = {
    "m_iClip1": 0x1928,          # int 弹匣内子弹（实测 Glock=20, AWP=5, SG556=30）
    "m_iClip2": 0x192C,          # int 副弹匣，常规为 -1
    "m_iItemDefinitionIndex": 0x1BA,
    "m_iEntityQuality": 0x1BC,
    "m_AttributeManager": 0x1290,
    "m_bDisallowSOC": 0x1E9,
    "m_bInitialized": 0x1E8,
    "m_iItemIDHigh": 0x1D0,
    "m_iItemIDLow": 0x1D4,
    "m_iBurstShotsRemaining": 0x1F24,
}

# ============ 七、相机服务 ============
CAMERA_SERVICES = {
    "m_iFOV": 0x298,
    "m_iFOVStart": 0x29C,
    "m_flFOVTime": 0x2A0,
    "m_flFOVRate": 0x2A4,
    "m_vecCsViewPunchAngle": 0x48,
    "m_flCameraSpeed": 0x628,
}

# ============ 八、controller（CCSPlayerController） ============
CONTROLLER = {
    "m_hPlayerPawn": 0x92C,      # 持有的 pawn 句柄（实测 0xF3812F -> idx 303）
    "m_iPing": 0x838,
    "m_bPawnHasDefuser": 0x940,
    "m_bPawnHasHelmet": 0x941,
    "m_bIsPlayerNameDirty": 0x974,
    "m_iAccount": 0x40,          # 该字段名在 schema 里重名，取到的是首个匹配，用前需复核
}

# ============ 九、通用实体 ============
ENTITY = {
    "m_bSpotted": 0x8,           # 被雷达标记
    "m_bSpottedByMask": 0xC,     # uint32[2]
    "m_hOwnerEntity": 0x520,
    "m_hGroundEntity": 0x530,
    "m_vecAbsOrigin": 0xC8,
    "m_teamNum": 0x3E7,
}


# ---------------------------------------------------------------- 便捷访问器
def bind(mod):
    """把本表挂到你的读取模块上（mod 需要提供 q/rd/i32/f32/vec）。"""
    mod.GLOBAL = GLOBAL
    mod.PAWN = PAWN
    mod.WEAPON = WEAPON
    mod.WEAPON_SERVICES = WEAPON_SERVICES
    mod.CAMERA_SERVICES = CAMERA_SERVICES
    mod.CONTROLLER = CONTROLLER
    mod.BONE = BONE
    return mod


def entity_system(mod):
    return mod.q(mod.CB + GLOBAL["dwEntityList"])


def identity_base(mod):
    """identity(0) 的地址基准：B0 = *(ES+0x10) - 0x38。"""
    es = entity_system(mod)
    return mod.q(es + 0x10) - IDENTITY["base_delta"] if es else None


def identity(mod, idx):
    """CEntityIdentity* for entity index idx（实体表里的节点本身）。"""
    b0 = identity_base(mod)
    return b0 + IDENTITY["stride"] * idx if b0 else None


def instance(mod, idx):
    """游戏对象（C_BaseEntity* 等）：identity + 0x38 处存的就是实例指针。"""
    idn = identity(mod, idx)
    if not idn:
        return None
    p = mod.q(idn + IDENTITY["instance"])
    return p if p and p > 0x10000 else None


def handle_index(h):
    return h & HANDLE_INDEX_MASK


def local_controller(mod):
    return mod.q(mod.CB + GLOBAL["dwLocalPlayerController"])


def local_pawn(mod):
    return mod.q(mod.CB + GLOBAL["dwLocalPlayerPawn"])


def view_matrix(mod):
    """返回 4x4（行主序，list[list[float]]）。"""
    raw = mod.rd(mod.CB + GLOBAL["dwViewMatrix"], 64)
    if not raw or len(raw) < 64:
        return None
    import struct as _s
    f = _s.unpack("<16f", raw)
    return [list(f[0:4]), list(f[4:8]), list(f[8:12]), list(f[12:16])]


def bone_array(mod, pawn):
    import struct as _s
    skel = mod.q(pawn + PAWN["m_pSceneNode"])
    if not skel:
        return None
    ms = mod.q(skel + SCENE_NODE["bone_array_rel"])
    if not ms:
        return None
    return mod.q(ms + MODEL_STATE["m_pBoneArray"])


def bone_pos(mod, arr, i):
    import struct as _s
    raw = mod.rd(arr + BONE["stride"] * i, 12)
    return _s.unpack("<3f", raw) if raw else None


def bones(mod, pawn, count=128, max_dist=250.0):
    """一次性批量读骨架：返回 {索引: (x,y,z)}，已过滤零值/异常值/离原点过远的填充项。"""
    import struct as _s
    import math as _m
    arr = bone_array(mod, pawn)
    sn = mod.q(pawn + PAWN["m_pSceneNode"])
    if not arr or not sn:
        return {}
    o = mod.vec(sn + SCENE_NODE["m_vecAbsOrigin"])
    if not o:
        return {}
    raw = mod.rd(arr, BONE["stride"] * count)   # 一次读整块，比逐根读快 ~30 倍
    if not raw:
        return {}
    out = {}
    for i in range(len(raw) // BONE["stride"]):
        x, y, z = _s.unpack_from("<3f", raw, BONE["stride"] * i)
        if not all(map(_m.isfinite, (x, y, z))):
            continue
        if abs(x) + abs(y) + abs(z) < 1e-6:
            continue
        if _m.dist((x, y, z), o) > max_dist:
            continue
        out[i] = (x, y, z)
    return out


def origin(mod, ent):
    """任何 C_BaseEntity/C_CSPlayerPawn 的世界坐标（统一走 scene node）。"""
    sn = mod.q(ent + PAWN["m_pSceneNode"])
    return mod.vec(sn + SCENE_NODE["m_vecAbsOrigin"]) if sn else None


def eye_pos(mod, pawn):
    """眼睛位置 = 原点 + m_vecViewOffset。"""
    o = origin(mod, pawn)
    v = mod.vec(pawn + PAWN["m_vecViewOffset"])
    if not o or not v:
        return None
    return (o[0] + v[0], o[1] + v[1], o[2] + v[2])


def eye_angles(mod, pawn):
    """(pitch, yaw)。yaw 0=+X 轴，角度制。"""
    v = mod.vec(pawn + PAWN["m_angEyeAngles"])
    return (v[0], v[1]) if v else (0.0, 0.0)


def view_angles(mod):
    """全局视角角 (pitch, yaw, roll)，读自 dwViewAngles 数组槽 0。"""
    import struct as _s
    raw = mod.rd(mod.CB + GLOBAL["dwViewAngles"], 12)
    return _s.unpack("<3f", raw) if raw and len(raw) == 12 else None


def forward(angles, dist=1.0):
    """由 (pitch,yaw) 求前方向量（CS 约定：yaw 0 = +X，pitch 负 = 抬头）。"""
    import math as _m
    p, y = _m.radians(angles[0]), _m.radians(angles[1])
    return (_m.cos(y) * _m.cos(p), _m.sin(y) * _m.cos(p), -_m.sin(p))


def active_weapon(mod, pawn):
    """返回 (武器实例指针, 武器类名, 弹匣内子弹)。"""
    ws = mod.q(pawn + PAWN["m_pWeaponServices"])
    if not ws:
        return None, None, None
    raw = mod.rd(ws + WEAPON_SERVICES["m_hActiveWeapon"], 4)
    if not raw:
        return None, None, None
    import struct as _s
    w = instance(mod, _s.unpack("<I", raw)[0] & HANDLE_INDEX_MASK)
    if not w:
        return None, None, None
    return w, mod.vtname(mod.q(w)), mod.i32(w + WEAPON["m_iClip1"])


def players(mod, max_idx=0x4000):
    """枚举所有 C_CSPlayerPawn：yield (idx, ptr)。"""
    for i in range(max_idx):
        p = instance(mod, i)
        if not p:
            continue
        if mod.vtname(mod.q(p)) == "C_CSPlayerPawn":
            yield i, p


def project(m, p):
    """世界坐标 -> 归一化屏幕坐标 (-1..1)。返回 (sx, sy, w)。"""
    w = m[3][0] * p[0] + m[3][1] * p[1] + m[3][2] * p[2] + m[3][3]
    if w == 0:
        return None, None, 0.0
    sx = (m[0][0] * p[0] + m[0][1] * p[1] + m[0][2] * p[2] + m[0][3]) / w
    sy = (m[1][0] * p[0] + m[1][1] * p[1] + m[1][2] * p[2] + m[1][3]) / w
    return sx, sy, w
