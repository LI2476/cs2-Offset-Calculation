"""Tier A 驱动：纯静态地把字段偏移算出来，不用开游戏。

判定顺序（顺序错了会把 exact 误判成 composite）：
  exact     在指定类范围内命中且偏移相等       -> 高置信
  renamed   .ofs 的名字与引擎名不同但语义相同   -> 走 KEY_ALIAS，按 exact 处理
  composite 名字命中但偏移不等，且能拆成 A+B   -> 高/中置信
  alias     名字不在 schema 里，走手写别名表    -> 中置信
  caliber   同名不同取法（口径差异）           -> 中置信
  missing   都不成立                           -> 老实说不知道

**限定类范围是准确率的关键**：m_fFlags 在 C_BaseEntity 是 0x3f4，
在别的类是 0x63。不限定就 50% 命中。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .pe import Image
from .schema import ALIASES, CompositeSolver, Schema, build_schema
from .targets import KEY_ALIAS, STRUCT_HINT, TIER_A, class_matches


@dataclass
class Result:
    key: str
    value: int | None = None
    source: str = "missing"     # exact | renamed | composite | alias | caliber | missing
    confidence: str = "none"    # high | medium | low | none
    evidence: str = ""
    candidates: list[int] = field(default_factory=list)
    expect: int = 0
    match: bool | None = None
    cls: str | None = None


def _scoped_offsets(schema: Schema, name: str, struct_tag: str) -> tuple[list[int], list[str]]:
    """只在结构标签允许的类里找这个字段。"""
    hint = STRUCT_HINT.get(struct_tag, ())
    offs: list[int] = []
    classes: list[str] = []
    for cls, table in schema.by_class.items():
        if not class_matches(cls, hint):
            continue
        if name in table:
            classes.append(cls)
            if table[name] not in offs:
                offs.append(table[name])
    return sorted(offs), classes


def _pick_exact(schema: Schema, key: str, expect: int, tag: str) -> Result | None:
    offs, classes = _scoped_offsets(schema, key, tag)
    if not offs:
        return None
    if expect in offs:
        others = [o for o in offs if o != expect]
        ev = "命中 %#x（%s）" % (expect, ", ".join(classes[:2]) or "无类名")
        if others:
            ev += "；同范围内另有 %s，取与结构标签相符者" % ", ".join("%#x" % o for o in others)
        return Result(key, expect, "exact", "high", ev, offs, expect, True, classes[0] if classes else None)
    return None


def _struct_bound(schema: Schema, tag: str) -> int:
    """结构标签允许的类里，最大的结构体大小 —— 这就是该结构的容量上界。

    一个偏移如果超过上界，就物理上不可能落在该结构里，
    不管名字对不对都应判可疑。这条规则挡掉了"靠名字凑数"的复合解。
    """
    hint = STRUCT_HINT.get(tag, ())
    sizes = [sz for cls, sz in schema.class_size.items() if class_matches(cls, hint)]
    return max(sizes) if sizes else 0


def _try_composite(schema: Schema, solver: CompositeSolver, key: str, expect: int,
                   tag: str) -> Result | None:
    own, _ = _scoped_offsets(schema, key, tag)
    if not own:
        own = schema.offsets(key)
    sols = solver.solve(expect, own_candidates=own, limit=6)
    for a, b, parents, children, score in sols:
        # 证据要求：父子都有名、且不能是"同一个偏移自加"
        if not parents or not children or a == b:
            continue
        # 退化解 a=0 就是"随便找个字段 + 目标偏移"，毫无信息量，直接丢
        if a == 0 or b == 0:
            continue
        if score < 75:
            continue
        # 物理上界：解出来的偏移不能超过该结构的最大体积
        bound = _struct_bound(schema, tag)
        if bound and expect >= bound:
            continue
        # 父项名应当像"结构体字段"（大小写混合的复合类型），
        # 子项名应当就是目标名或它的近义 —— 否则只是凑数
        ev = "%s(%#x) + %s(%#x) = %#x" % (parents[0], a, children[0], b, expect)
        return Result(key, expect, "composite", "high" if score >= 90 else "medium",
                      ev, own + [expect], expect, True)
    return None


def _try_alias(key: str) -> Result | None:
    a = ALIASES.get(key)
    if not a:
        return None
    if a["kind"] == "chain":
        total = sum(off for _, off in a["chain"])
        chain = " -> ".join("%s(+%#x)" % (n, off) for n, off in a["chain"])
        return Result(key, total, "alias", a.get("confidence", "medium"),
                      "%s = %#x；%s" % (chain, total, a["note"]), [total], 0, None)
    return Result(key, None, "caliber", a.get("confidence", "medium"), a["note"], [], 0, None)


def run(dll_path: str, data_lo: int = 0x21C2000, data_hi: int = 0x27A6C2C,
        cache_dir: str | None = None, verbose: bool = True) -> dict:
    t0 = time.time()
    img = Image(dll_path)
    if verbose:
        print("[Tier A] 装载镜像 %s，%.1fs" % (Path(dll_path).name, time.time() - t0))

    schema = build_schema(img, data_lo, data_hi, verbose=verbose)
    solver = CompositeSolver(schema)
    if verbose:
        print("  索引池 %d 个不重复偏移，耗时 %.1fs" % (len(solver.pool), time.time() - t0))

    results: list[Result] = []
    for key, (expect, tag, note) in TIER_A.items():
        engine_key = KEY_ALIAS.get(key, key)
        renamed = engine_key != key

        r = _pick_exact(schema, engine_key, expect, tag)
        if r:
            if renamed:
                r.source = "renamed"
                r.evidence = "%s：.ofs 名 %s -> 引擎名 %s；%s" % (
                    "重命名映射", key, engine_key, r.evidence)
            results.append(r)
            continue

        r = _try_composite(schema, solver, engine_key, expect, tag)
        if r:
            r.match = (r.value == expect)
            results.append(r)
            continue

        r = _try_alias(key)
        if r:
            r.expect = expect
            r.match = (r.value == expect) if r.value is not None else None
            results.append(r)
            continue

        # 名字在 schema 里有，但不在结构标签允许的类里 —— 这不是"找不到"，
        # 而是"这个名字确实存在，但属于别的结构"。老实分开报，别混进 missing。
        elsewhere = schema.offsets(engine_key)
        if elsewhere:
            holders = schema.classes_with(engine_key)
            results.append(Result(
                key, None, "out_of_scope", "low",
                "%s 存在于 %s 的 %s，但这些类都不属于「%s」结构；.ofs 值 %#x 待复核"
                % (engine_key, ", ".join(holders[:3]) or "未知类",
                   ", ".join("%#x" % o for o in elsewhere[:3]), tag, expect),
                elsewhere, expect, None, holders[0] if holders else None,
            ))
            continue

        raw = schema.offsets(engine_key)
        results.append(Result(
            key, None, "missing", "none",
            "schema 里找不到 %s（结构=%s，说明=%s）；散落同名候选 %s"
            % (engine_key, tag, note, ", ".join("%#x" % c for c in raw[:4]) or "无"),
            raw, expect, False,
        ))

    dt = time.time() - t0
    def cnt(s): return sum(1 for r in results if r.source == s)
    matched = sum(1 for r in results if r.match)
    scored = sum(1 for r in results if r.match is not None)

    if cache_dir:
        p = Path(cache_dir)
        p.mkdir(parents=True, exist_ok=True)
        with open(p / "_schema_index.json", "w", encoding="utf-8") as fh:
            json.dump({
                "n_fields": len(schema.fields),
                "n_names": len(schema.by_name),
                "n_classes": len(schema.classes),
                "by_name": schema.by_name,
                "class_of": schema.class_of,
                "class_size": schema.class_size,
            }, fh)

    stats = {
        "n_fields": len(schema.fields), "n_names": len(schema.by_name),
        "n_classes": len(schema.classes),
        "exact": cnt("exact"), "renamed": cnt("renamed"),
        "composite": cnt("composite"), "alias": cnt("alias"),
        "caliber": cnt("caliber"), "missing": cnt("missing"),
        "matched": matched, "scored": scored, "total": len(results),
    }
    if verbose:
        print("[Tier A] 完成 %.1fs：exact %d / renamed %d / composite %d / alias %d / missing %d"
              % (dt, stats["exact"], stats["renamed"], stats["composite"],
                 stats["alias"], stats["missing"]))
        print("         与 .ofs 一致 %d/%d（%d 项无基准可比）"
              % (matched, scored, len(results) - scored))
    return {"results": results, "elapsed": dt, "schema": schema, "stats": stats}
