"""字段描述表解析：把 client.dll 里那张"类 -> 字段 -> 偏移"的表挖出来。

表结构（本机实测，反推出来的，改动前请先用 _p_cls2.py 复验）：

    字段描述项（0x20 字节）:
        +0x00  qword  指向字段名字符串的 VA       ("m_iHealth")
        +0x08  qword  类型码                      (0xf00000000000000a 之类)
        +0x10  uint32 偏移                        (0x34c)
        +0x18  uint32 保留

    类描述符（字段数组之前 0x28 字节处）:
        p - 0x28   类名字符串 VA                  ("C_BaseEntity")
        p - 0x10   uint32 结构体大小
        p - 0x0C   uint32 [低16位=字段数, 高16位=静态字段数]
        p + 0x00   指向字段数组首项的 VA
        p + 0x08 / +0x10  其它表（父类链之类）

关键：**必须**按类描述符给的字段数展开，不能靠"相邻 0x20"聚段。
实测 656 个 run 里有 27 个中间断裂（某个字段名恰好被别处也引用），
按相邻聚段会少算字段，进而把正确的类归属判错。

这是 Tier A 不需要进程的原因：全在磁盘文件里。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .pe import Image

DESC_STRIDE = 0x20
OFF_AT = 0x10
TYPE_AT = 0x08
CLS_NAME_BACK = 0x28
CLS_SIZE_BACK = 0x10
CLS_COUNT_BACK = 0x0C


@dataclass
class FieldDesc:
    name: str
    offset: int
    type_code: int
    desc_rva: int            # 这个描述项自身的 RVA
    name_rva: int            # 字段名字符串的 RVA
    cls: str | None = None   # 所属类名


@dataclass
class ClassDesc:
    name: str
    size: int
    n_fields: int
    n_static: int
    fields_rva: int
    desc_rva: int


@dataclass
class Schema:
    fields: list[FieldDesc] = field(default_factory=list)
    classes: list[ClassDesc] = field(default_factory=list)
    by_name: dict[str, list[int]] = field(default_factory=dict)
    by_class: dict[str, dict[str, int]] = field(default_factory=dict)
    class_of: dict[str, str] = field(default_factory=dict)
    class_size: dict[str, int] = field(default_factory=dict)

    def offsets(self, name: str) -> list[int]:
        return self.by_name.get(name, [])

    def classes_with(self, name: str) -> list[str]:
        return [c for c, m in self.by_class.items() if name in m]

    def offset_in(self, cls: str, name: str) -> int | None:
        return self.by_class.get(cls, {}).get(name)

    # ------------------------------------------------------------ 缓存
    def save(self, path: str) -> str:
        """存盘。构一次要 73 秒，缓存下来下次秒开（键是 DLL 的时间戳）。"""
        import json
        from pathlib import Path
        payload = {
            "by_name": self.by_name,
            "by_class": self.by_class,
            "class_of": self.class_of,
            "class_size": self.class_size,
            "n_fields": len(self.fields),
            "n_classes": len(self.classes),
        }
        Path(path).write_text(json.dumps(payload, ensure_ascii=False),
                              encoding="utf-8")
        return path

    @staticmethod
    def load(path: str) -> "Schema | None":
        import json
        from pathlib import Path
        p = Path(path)
        if not p.exists():
            return None
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return Schema(by_name=d["by_name"], by_class=d["by_class"],
                          class_of=d.get("class_of", {}),
                          class_size=d.get("class_size", {}))
        except Exception:
            return None


def _is_class_name(s: str | None) -> bool:
    if not s or not (3 <= len(s) <= 90):
        return False
    if not (s[0].isalpha() or s[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in s)


def load_or_build_schema(img: Image, data_lo: int, data_hi: int,
                         cache_dir, verbose: bool = False) -> Schema:
    """带缓存的 build_schema。

    **为什么要缓存**：实测 build_schema 要 73 秒（4.3 MB 的 .data 里逐条
    验证 4334 个字段描述项）。开发时每跑一次扫描器都重算一遍，根本没法迭代。
    缓存键用 DLL 的编译时间戳 —— 游戏一更新，戳变了，自动重建，不会读到旧表。
    """
    from pathlib import Path
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    stamp = getattr(img, "timestamp", 0) or 0
    path = cache_dir / ("schema_%08x.json" % stamp)
    sc = Schema.load(str(path))
    if sc is not None:
        if verbose:
            print("  schema 命中缓存（%d 字段 / %d 类）"
                  % (len(sc.by_name), len(sc.by_class)))
        return sc
    sc = build_schema(img, data_lo, data_hi, verbose=verbose)
    sc.save(str(path))
    if verbose:
        print("  schema 已建索引并缓存 → %s" % path)
    return sc


def build_schema(img: Image, data_lo: int, data_hi: int, verbose: bool = False) -> Schema:
    # ---- 1. 所有"字段名指针"出现的位置 ----
    cand_desc: dict[int, tuple[str, int]] = {}
    for rva, text in img.iter_cstrings(2, 120):
        if not text.startswith("m_") or not all(c.isalnum() or c == "_" for c in text):
            continue
        pat = struct.pack("<Q", img.to_va(rva))
        for p in img.find_bytes(pat, data_lo, data_hi):
            if p % 8 == 0 and p >= data_lo + DESC_STRIDE:
                cand_desc[p] = (text, rva)

    # ---- 2. 从候选里认出真正的"字段数组首项" ----
    # 真首项的判据：它被某个 qword 引用，且该引用位置 - 0x28 是类名，
    # -0x0C 的字段数在合理范围，并且紧跟的下一项也是 m_ 开头（字段数 > 1 时）
    schema = Schema()
    claimed: set[int] = set()

    for head_rva in sorted(cand_desc):
        if head_rva in claimed:
            continue
        refs = list(img.find_bytes(struct.pack("<Q", img.to_va(head_rva)), data_lo, data_hi))
        if not refs:
            continue
        p = refs[0]
        if p < data_lo + CLS_NAME_BACK:
            continue
        cls = img.ptr_cstr(p - CLS_NAME_BACK, 90)
        if not _is_class_name(cls):
            continue
        size = img.u32(p - CLS_SIZE_BACK)
        cnt = img.u32(p - CLS_COUNT_BACK)
        n_fields, n_static = cnt & 0xFFFF, cnt >> 16
        if not (1 <= n_fields <= 400) or size > 0x40000:
            continue
        # 字段数 >1 时，第二项必须是 m_ 开头（否则是误认）
        if n_fields > 1:
            nxt = img.ptr_cstr(head_rva + DESC_STRIDE, 120)
            if not nxt or not nxt.startswith("m_"):
                continue

        cdesc = ClassDesc(cls, size, n_fields, n_static, head_rva, p)
        schema.classes.append(cdesc)
        schema.class_size[cls] = size
        table = schema.by_class.setdefault(cls, {})

        for i in range(n_fields):
            drva = head_rva + DESC_STRIDE * i
            nm = img.ptr_cstr(drva, 120)
            if not nm or not nm.startswith("m_"):
                continue        # 真实数据里偶有空位，跳过而不是截断
            claimed.add(drva)
            off = img.u32(drva + OFF_AT)
            if off > 0x100000:
                continue
            fd = FieldDesc(nm, off, img.q(drva + TYPE_AT), drva,
                           img.to_rva(img.q(drva)) or 0, cls)
            schema.fields.append(fd)
            table.setdefault(nm, off)
            schema.by_name.setdefault(nm, [])
            if off not in schema.by_name[nm]:
                schema.by_name[nm].append(off)

    # ---- 3. 没被类描述符覆盖的散落项：仍然收，但不给类名 ----
    for drva, (nm, name_rva) in cand_desc.items():
        if drva in claimed:
            continue
        off = img.u32(drva + OFF_AT)
        if off > 0x100000:
            continue
        schema.fields.append(FieldDesc(nm, off, img.q(drva + TYPE_AT), drva, name_rva, None))
        schema.by_name.setdefault(nm, [])
        if off not in schema.by_name[nm]:
            schema.by_name[nm].append(off)

    for nm in schema.by_name:
        schema.by_name[nm].sort()

    # ---- 4. 默认类归属：优先"类里字段最多"的那个（子类覆盖父类） ----
    votes: dict[str, dict[str, int]] = {}
    for fd in schema.fields:
        if not fd.cls:
            continue
        v = votes.setdefault(fd.name, {})
        v[fd.cls] = schema.class_size.get(fd.cls, 0)
    for nm, v in votes.items():
        schema.class_of[nm] = max(v.items(), key=lambda kv: kv[1])[0]

    if verbose:
        print(
            "  schema: %d 个字段描述项, %d 个唯一名字, %d 个类（已归属 %d 项）"
            % (len(schema.fields), len(schema.by_name), len(schema.classes),
               sum(1 for f in schema.fields if f.cls))
        )
    return schema


# ============================================================ 别名与口径
# 全自动流程里唯一需要人工维护的地方。
# 原因：这类字段在引擎 schema 里没有同名项，是靠语义对应出来的，
# 机器无从推断"哪个名字对应哪个语义"。条目少、改动少，成本可接受。
ALIASES: dict[str, dict] = {
    "m_vecOrigin": {
        "kind": "chain",
        "chain": [("m_pGameSceneNode", 0x0), ("CGameSceneNode::m_vecOrigin", 0x80)],
        "note": "引擎 schema 无此名；sceneNode + 0x80 是局部坐标字段",
        "confidence": "medium",
    },
    "m_dwBoneMatrix": {
        "kind": "chain",
        "chain": [("m_pGameSceneNode", 0x378), ("m_pModelState", 0x80)],
        "note": "引擎 schema 无此名；骨骼矩阵要走 sceneNode->modelState->CTransform[]",
        "confidence": "medium",
    },
    "m_iItemDefinitionIndex": {
        "kind": "caliber",
        "note": "schema 的 0x1ba 是武器对象(self)内偏移；.ofs 的 0x149a 是从 pawn 直取",
        "confidence": "medium",
    },
}


# ============================================================ 复合偏移合成
class CompositeSolver:
    """当"名字命中但偏移不等"时，搜 A + B = target。

    现实依据（本机实测）：
        m_bSpotted  schema 里叫 m_bSpotted 偏移 0x8，嵌在 m_entitySpottedState(0x1e88)
                    → 0x1e88 + 0x8 = 0x1e90，正好是 .ofs 的值
        m_predictableBaseAngle  schema 0x50，.ofs 0x88 = 0x50 + 0x38
    """

    def __init__(self, schema: Schema, pool_max: int = 0x8000):
        self.schema = schema
        self.pool = sorted({o for v in schema.by_name.values() for o in v if o <= pool_max})
        self.pool_set = set(self.pool)
        # 偏移 -> 拥有它的字段名（用于解释）
        self.owner: dict[int, list[str]] = {}
        for nm, vs in schema.by_name.items():
            for v in vs:
                self.owner.setdefault(v, []).append(nm)

    def solve(self, target: int, own_candidates: list[int] = (), limit: int = 6):
        out: list[tuple[int, int, bool]] = []
        seen: set[tuple[int, int]] = set()
        for a in own_candidates:
            b = target - a
            if 0 < b and b in self.pool_set and (a, b) not in seen:
                seen.add((a, b))
                out.append((a, b, True))
        for a in self.pool:
            b = target - a
            if 0 < b and b in self.pool_set and (a, b) not in seen:
                seen.add((a, b))
                out.append((a, b, False))

        res = []
        for a, b, strong in out:
            parents = self.owner.get(a, [])
            children = self.owner.get(b, [])
            if not parents or not children:
                continue
            score = 40
            if strong:
                score += 35
            # 父项名和子项名共享词干（entity/Spotted 这种）→ 明显是"父结构里的子字段"
            for pname in parents:
                stem = pname[2:].split("_")[0][:6].lower() if len(pname) > 2 else ""
                for cname in children:
                    if stem and stem in cname.lower():
                        score += 10
            if len(parents) == 1 and len(children) == 1:
                score += 5
            res.append((a, b, parents[:3], children[:3], min(score, 100)))
        res.sort(key=lambda x: (-x[4], x[0]))
        return res[:limit]
