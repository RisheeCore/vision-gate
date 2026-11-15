"""Deterministic Fidelity & Provenance Gate: rejects LLM rewrites that drop hazards silently."""

def extract_wanted_hazards(findings: list[dict], primary_rule: str | None) -> set[str]:
    want = {str(f["rule"]) for f in findings if f.get("rule")}
    if not want and primary_rule and primary_rule != "R00":
        want.add(str(primary_rule))
    return want

def verify_provenance(want: set[str], provenance: dict) -> dict:
    preserved = {str(x) for x in provenance.get("preserved", [])}
    dropped = {str(x) for x in provenance.get("dropped", [])}
    overlap = sorted(preserved & dropped)
    accounted = preserved | dropped
    missing = sorted(want - accounted)
    invented = sorted(accounted - want)
    ok = (len(missing) == 0) and (len(overlap) == 0)
    return {
        "ok": ok,
        "missing": missing,
        "overlap": overlap,
        "invented": invented,
        "preserved": sorted(preserved),
        "dropped": sorted(dropped),
        "why": str(provenance.get("why", "")).strip(),
    }
