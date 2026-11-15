import json
import pathlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def generate_reports(eval_summary_path: pathlib.Path, out_dir: pathlib.Path) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = json.loads(eval_summary_path.read_text(encoding="utf-8"))
    versions = sorted(summary.keys())
    created: list[str] = []

    rates = [summary[v]["block_rate"] * 100 for v in versions]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(versions, rates, marker="o", linewidth=2, label="Block Rate (%)")
    ax.set_ylim(0, 105)
    ax.set_xlabel("Policy Version")
    ax.set_ylabel("Block Rate (%)")
    ax.set_title("C1: Malicious Payload Block Rate by Policy Version")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend()
    c1_path = out_dir / "C1_block_rate_by_version.png"
    fig.savefig(c1_path, bbox_inches="tight")
    plt.close(fig)
    created.append(str(c1_path))

    last_v = versions[-1]
    per_cat = summary[last_v].get("per_category", {})
    if per_cat:
        cats = list(per_cat.keys())
        cat_rates = [per_cat[c]["rate"] * 100 for c in cats]
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.bar(cats, cat_rates)
        ax.set_ylim(0, 105)
        ax.set_ylabel("Block Rate (%)")
        ax.set_title(f"C2: {last_v} Block Rate by Category")
        plt.xticks(rotation=30, ha="right")
        c2_path = out_dir / "C2_category_block_rate.png"
        fig.savefig(c2_path, bbox_inches="tight")
        plt.close(fig)
        created.append(str(c2_path))

    fprs = [summary[v]["fpr"] * 100 for v in versions]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(versions, fprs, color="orange")
    ax.set_ylabel("False Positive Rate (%)")
    ax.set_title("C6: Benign False-Positive Rate by Policy Version")
    c6_path = out_dir / "C6_fpr_by_version.png"
    fig.savefig(c6_path, bbox_inches="tight")
    plt.close(fig)
    created.append(str(c6_path))

    md_lines = [
        "# VISION Evaluation Report",
        "",
        "| Version | Malicious N | Block Rate | 95% Wilson CI | Sandbox Contained | Escapes | Benign FPR |",
        "|---|---|---|---|---|---|---|",
    ]
    for v in versions:
        s = summary[v]
        ci = s["block_ci"]
        md_lines.append(
            f"| {v} | {s['malicious_n']} | {s['block_rate']*100:.1f}% | [{ci[0]*100:.1f}%, {ci[1]*100:.1f}%] "
            f"| {s['sandbox_contained']} | {s['escaped']} (<= {s['escape_upper_bound']}) | {s['fpr']*100:.1f}% |"
        )
    t_path = out_dir / "TABLES.md"
    t_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    created.append(str(t_path))
    return created
