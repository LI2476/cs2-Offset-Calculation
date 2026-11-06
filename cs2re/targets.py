"""目标键表：这份工具要复现哪些偏移。

**基准值直接抄自 offsets.py（本机活进程验证过的真值）。**
这里绝不允许"把基准改成工具算出来的值" —— 那就是自欺欺人。
工具只读值做 diff，不用它去凑答案。

每条 = (基准值, 结构标签, 说明)
结构标签用来**限定搜索范围**：字段名在引擎里重名很常见
（比如 m_fFlags 同时存在于 C_BaseEntity@0x3f4 和某个类@0x63），
不给范围就只能瞎猜。STRUCT_HINT 给出每个标签该看哪些类。
"""

# 结构标签 -> 该类下的类名关键词（子串匹配）
STRUCT_HINT: dict[str, tuple[str, ...]] = {
    "pawn":            ("PlayerPawn", "C_BaseEntity", "C_BaseModelEntity"),
    "controller":      ("PlayerController",),
    "weapon":          ("EconItemView", "C_BasePlayerWeapon", "C_CSWeaponBase",
                        "CAttributeContainer", "C_EconEntity"),
    "weaponServices":  ("WeaponServices",),
    "cameraServices":  ("CameraServices",),
    "sceneNode":       ("CGameSceneNode",),
    "modelState":      ("CModelState", "CSkeletonInstance"),
    "entity":          ("EntitySpottedState_t", "C_BaseEntity", "C_BaseModelEntity"),
    # ---- 2026-11-04 补：对齐 .ofs 表的剩余字段 ----
    "aimPunch":        ("AimPunchServices",),
    "observerServices": ("ObserverServices", "C_BasePlayerPawn"),
    "actionTracking":  ("ActionTrackingServices",),
    "plantedC4":       ("PlantedC4",),
}

# ---------------------------------------------------------------- Tier A（纯静态）
TIER_A: dict[str, tuple[int, str, str]] = {
    # ---- PAWN / 父类 ----
    "m_iHealth":              (0x34C,  "pawn", "血量"),
    "m_iMaxHealth":           (0x348,  "pawn", "最大血量"),
    "m_lifeState":            (0x354,  "pawn", "存活状态"),
    "m_iTeamNum":             (0x3E7,  "pawn", "队伍"),
    "m_ArmorValue":           (0x1ED0, "pawn", "护甲"),
    "m_fFlags":               (0x3F4,  "pawn", "状态位"),
    "m_vecVelocity":          (0x430,  "pawn", "速度"),
    "m_vecViewOffset":        (0xF60,  "pawn", "眼高偏移"),
    "m_angEyeAngles":         (0x3600, "pawn", "视线角"),
    "m_iShotsFired":          (0x1EB8, "pawn", "连发计数"),
    "m_pGameSceneNode":       (0x330,  "pawn", "场景节点指针（= .ofs 的 m_pSceneNode）"),
    "m_pWeaponServices":      (0x12F0, "pawn", "武器服务"),
    "m_pCameraServices":      (0x1328, "pawn", "相机服务"),
    "m_pAimPunchServices":    (0x1598, "pawn", "后坐力服务"),
    "m_pMovementServices":    (0x1330, "pawn", "移动服务"),
    "m_pBulletServices":      (0x1570, "pawn", "弹道服务"),
    "m_pRenderComponent":     (0x338,  "pawn", "渲染组件"),
    "m_hController":          (0x14BC, "pawn", "所属 controller 句柄"),
    # ---- CONTROLLER ----
    "m_hPlayerPawn":          (0x92C,  "controller", "持有的 pawn 句柄"),
    "m_iPing":                (0x838,  "controller", "延迟"),
    "m_bPawnHasDefuser":      (0x940,  "controller", "有拆弹器"),
    "m_bPawnHasHelmet":       (0x941,  "controller", "有头盔"),
    "m_bIsPlayerNameDirty":   (0x974,  "controller", "名字脏标记"),
    # ---- WEAPON ----
    "m_hMyWeapons":           (0x48,   "weaponServices", "武器句柄数组"),
    "m_hActiveWeapon":        (0x60,   "weaponServices", "当前武器句柄"),
    "m_hLastWeapon":          (0x64,   "weaponServices", "上一把武器"),
    "m_iItemDefinitionIndex": (0x1BA,  "weapon", "物品定义索引"),
    "m_iEntityQuality":       (0x1BC,  "weapon", "品质"),
    "m_AttributeManager":     (0x1290, "weapon", "属性管理器"),
    "m_bInitialized":         (0x1E8,  "weapon", "已初始化"),
    "m_bDisallowSOC":         (0x1E9,  "weapon", "禁止 SOC"),
    "m_iItemIDHigh":          (0x1D0,  "weapon", "itemID 高"),
    "m_iItemIDLow":           (0x1D4,  "weapon", "itemID 低"),
    "m_iBurstShotsRemaining": (0x1F24, "weapon", "点射余量"),
    # ---- CAMERA SERVICES ----
    "m_iFOV":                 (0x298,  "cameraServices", "视野"),
    "m_iFOVStart":            (0x29C,  "cameraServices", "视野起始"),
    "m_flFOVTime":            (0x2A0,  "cameraServices", "视野时间"),
    "m_flFOVRate":            (0x2A4,  "cameraServices", "视野速率"),
    "m_vecCsViewPunchAngle":  (0x48,   "cameraServices", "视角冲击角"),
    # 注意：0x628 曾被我当成 m_flCameraSpeed 写在这里，是错的。
    # CCSPlayer_CameraServices 的 class_size 实测只有 848 = 0x350，
    # 0x628 超出结构范围，实际属于 C_CSGO_MapPreviewCameraPathNode(size 1616)，
    # 语义完全不同。教训：class_size 可以直接当约束门 —— 字段偏移 >= class_size
    # 必然标错。所以这条从基准里去掉，等拿到正确的偏移再加回来。
    # ---- SCENE NODE / MODEL STATE ----
    "m_vecOrigin":            (0x80,   "sceneNode", "局部坐标"),
    "m_angAbsRotation":       (0xD4,   "sceneNode", "绝对旋转（.ofs 名 m_angAbsRotation）"),
    # ---- ENTITY / SPOTTED ----
    "m_bSpotted":             (0x8,    "entity", "被标记（EntitySpottedState_t 内）"),
    "m_bSpottedByMask":       (0xC,    "entity", "标记掩码"),
    "m_hOwnerEntity":         (0x520,  "entity", "拥有者句柄"),
    "m_hGroundEntity":        (0x530,  "entity", "地面实体句柄"),
    # ---- 2026-11-04 补：.ofs 里还有、本表原先缺的字段 ----
    "m_steamID":              (0x788,  "controller", "SteamID"),
    "m_iszPlayerName":        (0x6FC,  "controller", "玩家名"),
    "m_pActionTrackingServices": (0x828, "controller", "行动统计服务"),
    "m_hObserverPawn":        (0x930,  "controller", "观察者 pawn 句柄"),
    "m_iNumRoundKills":       (0x128,  "actionTracking", "本回合击杀数"),
    "m_flTotalRoundDamageDealt": (0x130, "actionTracking", "本回合总伤害"),
    "m_iIDEntIndex":          (0x36DC, "pawn", "准星所指实体索引"),
    "m_bIsScoped":            (0x1EA0, "pawn", "是否开镜"),
    "m_pObserverServices":    (0x1308, "observerServices", "观察者服务"),
    "m_hObserverTarget":      (0x4C,   "observerServices", "观察目标句柄"),
    "m_nBombSite":            (0x128C, "plantedC4", "炸弹安放点"),
    "m_flTimerLength":        (0x12C0, "plantedC4", "C4 倒计时长度"),
    "m_predictableBaseAngle": (0x50,   "aimPunch", "可预测基准角"),
}

# .ofs 里少数键的名字与引擎名不同（同一语义、不同命名），这里给映射。
# 不是"猜"，是明确记录"这两条是同一个东西"。
KEY_ALIAS: dict[str, str] = {
    "m_pSceneNode": "m_pGameSceneNode",        # .ofs 名 -> 引擎名
    "m_angAbsRotation": "m_angAbsRotation",
}

# .ofs 里那些**不是 schema 字段**的常量（骨骼步长、索引等），
# 工具算不出来也不该假装算得出来 —— 明确列出，报告里单列一栏。
NOT_SCHEMA: dict[str, str] = {
    "bone_stride": "骨骼步长 32（CTransform 大小，非字段偏移）",
    "bone_count_human": "人类模型骨骼数 110（运行时统计）",
    "bone_head_idx": "头骨索引 7（运行时按几何选）",
    "bone_neck_idx": "颈骨索引 25",
    "bone_pelvis_idx": "骨盆索引 0xC",
    "identity_stride": "CEntityIdentity 步长 0x70",
    "identity_instance": "identity+0x38 = 实例指针",
    "identity_base_delta": "B0 = *(ES+0x10) - 0x38",
    "handle_index_mask": "句柄低 15 位为索引",
}

# ---------------------------------------------------------------- Tier B（活内存）
#
# **2026-11-04 修正 dwViewAngles 的基准**：原表写 0x2580098，那是错的。
# 两条独立证据（不是"拿工具算出来的值当基准"）：
#   1. offsets.py:24 的 GLOBAL 表是 0x256F188，注释记录该值与矩阵反推 yaw
#      吻合到 0.000004 度；
#   2. 本轮活进程（PID 3384）直接读内存复核：
#        0x256F188 = (-0.0,      41.6298)  ← 与 dwViewMatrix 0x256F250 反推的
#                                            yaw 41.6298 一致
#        0x2580098 = (0.0,    -137.9794)  ← 与矩阵不符，是无关数据
# 0x2580098 代码引用数为 0 也不是"它是数据副本"的证据 —— 视角槽本来就可以
# 只被寄存器间接访问。旧基准错在这里被误读成结构特征。
#
# **2026-11-06 全部重定（游戏更新，build 6aebc4da）**：
# 旧值整体作废，新值全部由活进程闭合链核实，不是签名猜的：
#   dwLocalPlayerController 槽值 vtable 在模块内、自身句柄可取 →
#     句柄低 15 位 → ents[idx] 存在；dwLocalPlayerPawn 槽值 == 该 ents[idx]（3 次采样一致）
#   dwViewMatrix 与 dwViewAngles 互证：矩阵 forward 反推的 (pitch,yaw) 与角度槽
#     吻合到 0.0000 度（5 个同族候选里其余 4 个差 4.7~1781 度）
#   dwEntityList 枚举出 27 个实体、槽值不在模块内
TIER_B: dict[str, tuple[int, str]] = {
    "dwEntityList":             (0x271FBB8, "CGameEntitySystem*"),
    "dwLocalPlayerController":  (0x2542548, "CCSPlayerController*"),
    "dwLocalPlayerPawn":        (0x223F4C8, "C_CSPlayerPawn*"),
    "dwViewMatrix":             (0x2570250, "float[4][4]"),
    "dwViewAngles":             (0x2570188, "vec2 pitch/yaw"),
}

# ---------------------------------------------------------------- Tier C（弱证据）
TIER_C: dict[str, str] = {
    "dwSensitivity": "对象指针，指向的 struct 里没找到可信的灵敏度 float",
    "dwPlantedC4":   "C_PlantedC4*，当前槽值为 0（未在局内）",
    "dwGameTypes":   "CGameTypes*，基准未知",
}


def class_matches(cls: str, hint: tuple[str, ...]) -> bool:
    return any(h.lower() in cls.lower() for h in hint)


def all_targets() -> dict[str, int]:
    out = {k: v[0] for k, v in TIER_A.items()}
    out.update({k: v[0] for k, v in TIER_B.items()})
    return out
