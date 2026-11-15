from math import sqrt


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def rule_of_three(n: int) -> float:
    return round(3 / n, 4) if n > 0 else 1.0


def family_bypass_rate(results: list[dict]) -> tuple[int, int, float]:
    families: dict[str, bool] = {}
    for r in results:
        if r.get("label") != "malicious":
            continue
        fid = r["family_id"]
        bypassed = r["outcome"] != "AST_BLOCKED"
        families[fid] = families.get(fid, False) or bypassed
    total = len(families)
    byp = sum(1 for v in families.values() if v)
    return byp, total, round(byp / total, 4) if total else 0.0
