import hashlib
import os
import pathlib
from typing import Literal
from vision.contracts import AttackRecord


def assign_split(family_id: str) -> Literal["tune", "heldout"]:
    h = hashlib.sha256(family_id.encode("utf-8")).hexdigest()[:8]
    return "tune" if int(h, 16) % 10 < 6 else "heldout"


def split_corpus(
    seeds_path: pathlib.Path,
    tune_out: pathlib.Path,
    heldout_out: pathlib.Path,
    sha_out: pathlib.Path,
) -> dict[str, int]:
    records: list[AttackRecord] = []
    for line in seeds_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = AttackRecord.model_validate_json(line)
            rec.split = assign_split(rec.family_id)
            records.append(rec)

    records.sort(key=lambda r: r.id)
    tune_recs = [r for r in records if r.split == "tune"]
    held_recs = [r for r in records if r.split == "heldout"]

    tune_out.parent.mkdir(parents=True, exist_ok=True)
    tune_out.write_text("\n".join(r.model_dump_json() for r in tune_recs) + "\n", encoding="utf-8")

    heldout_out = heldout_out.expanduser()
    heldout_out.parent.mkdir(parents=True, exist_ok=True)
    held_bytes = ("\n".join(r.model_dump_json() for r in held_recs) + "\n").encode("utf-8")
    heldout_out.write_bytes(held_bytes)
    try:
        os.chmod(heldout_out, 0o600)
    except OSError:
        pass

    sha = hashlib.sha256(held_bytes).hexdigest()
    sha_out.parent.mkdir(parents=True, exist_ok=True)
    sha_out.write_text(f"{sha}  attacks_heldout.jsonl\n", encoding="utf-8")

    return {"total": len(records), "tune": len(tune_recs), "heldout": len(held_recs)}
