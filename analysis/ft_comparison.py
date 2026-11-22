"""ft_comparison.py — the headline figure + table for the report.

Compares the 4 prompt-based learning methods against the 4th method (QLoRA
fine-tuning), aggregating over all repeats found (<method>_r1, _r2, ...).

    python ft_comparison.py

The coarse IDS-alert scores saturate (single-vuln ceiling), so the discriminating
metric is DEFENSIVE COMPETENCE: in how many rounds did Blue actually block the
attacker, and how decisively (which step it blocked / patched on). Error bars span
the repeats.

Finding: fine-tuning reaches top-tier block reliability with NO runtime
reflection/memory/debrief — the defensive policy is internalised in the weights.
"""
import json, glob, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

METHODS = [("no_learning", "none"), ("reflect", "reflect"),
           ("reflect_mem", "+memory"), ("baseline", "+debrief"),
           ("ft", "FINE-TUNED")]
COLOR = {"none": "#8a8f98", "reflect": "#5b8def", "+memory": "#2bb673",
         "+debrief": "#e0a106", "FINE-TUNED": "#d7263d"}


def first_step(msgs, tool):
    s = 0
    for m in msgs:
        if m.get("role") == "assistant":
            if m.get("tool_calls"):
                for tc in m["tool_calls"]:
                    if tc["function"]["name"] == tool:
                        return s
                s += 1
    return None


def run_stats(run_dir):
    """Per-repeat stats for one runs/<method>_rN dir."""
    rounds = sorted(glob.glob(f"{run_dir}/round_*/scores.json"))
    if not rounds:
        return None
    det = [json.load(open(p))["detections"] for p in rounds]
    blocked = 0; bsteps = []; psteps = []
    for p in sorted(glob.glob(f"{run_dir}/round_*/blue_messages.json")):
        msgs = json.load(open(p, encoding="utf-8"))
        b = first_step(msgs, "block_ip"); pt = first_step(msgs, "patch_sqli")
        if b is not None:
            blocked += 1; bsteps.append(b)
        if pt is not None:
            psteps.append(pt)
    n = len(rounds)
    mean = lambda xs: float(np.mean(xs)) if xs else float("nan")
    return dict(n=n, det=det, block_rate=100.0 * blocked / n,
                avg_block_step=mean(bsteps), avg_patch_step=mean(psteps),
                mean_det=mean(det))


def agg(cfg):
    reps = [run_stats(d) for d in sorted(glob.glob(f"../runs/{cfg}_r*"))]
    reps = [r for r in reps if r]
    return reps


def ms(vals):
    vals = [v for v in vals if v == v]  # drop nan
    a = np.array(vals, float)
    return (float(a.mean()), float(a.max() - a.mean()), float(a.mean() - a.min())) if len(a) else (0, 0, 0)


def main():
    data = {}
    for cfg, lbl in METHODS:
        reps = agg(cfg)
        if reps:
            data[lbl] = reps
    names = [lbl for _, lbl in METHODS if lbl in data]
    cols = [COLOR[n] for n in names]
    nrep = {n: len(data[n]) for n in names}

    fig = plt.figure(figsize=(14, 4.8))
    x = np.arange(len(names))

    # Panel 1: block reliability (headline) with range bars
    ax1 = fig.add_subplot(1, 3, 1)
    br = [ms([r["block_rate"] for r in data[n]]) for n in names]
    means = [b[0] for b in br]
    yerr = [[b[2] for b in br], [b[1] for b in br]]
    ax1.bar(x, means, color=cols, yerr=yerr, capsize=4, error_kw=dict(ecolor="#333", lw=1))
    ax1.set_title("Defensive reliability:\nrounds attacker was blocked")
    ax1.set_ylabel("% of rounds blocked"); ax1.set_ylim(0, 108)
    for i, v in enumerate(means):
        ax1.text(i, min(v + 4, 103), f"{v:.0f}%", ha="center", fontsize=9)
    ax1.set_xticks(x); ax1.set_xticklabels(names, rotation=20)

    # Panel 2: decisiveness
    ax2 = fig.add_subplot(1, 3, 2)
    w = 0.38
    blk = [ms([r["avg_block_step"] for r in data[n]]) for n in names]
    pat = [ms([r["avg_patch_step"] for r in data[n]]) for n in names]
    ax2.bar(x - w / 2, [b[0] for b in blk], w, yerr=[[b[2] for b in blk], [b[1] for b in blk]],
            capsize=3, label="block step", color="#d7263d")
    ax2.bar(x + w / 2, [p[0] for p in pat], w, yerr=[[p[2] for p in pat], [p[1] for p in pat]],
            capsize=3, label="patch step", color="#2bb673")
    ax2.set_title("Decisiveness:\nstep of first block / patch (lower=faster)")
    ax2.set_ylabel("Blue step index"); ax2.set_xticks(x); ax2.set_xticklabels(names, rotation=20)
    ax2.legend(fontsize=8)

    # Panel 3: per-round detections (mean across repeats)
    ax3 = fig.add_subplot(1, 3, 3)
    for n in names:
        mats = np.array([r["det"] for r in data[n]])
        ax3.plot(range(mats.shape[1]), mats.mean(0), marker="o", ms=3, label=n,
                 color=COLOR[n], lw=2 if n == "FINE-TUNED" else 1)
    ax3.set_title("IDS detections / round (mean)"); ax3.set_xlabel("round")
    ax3.set_ylabel("alerts"); ax3.legend(fontsize=7); ax3.grid(True, alpha=0.3)

    reps_note = ", ".join(f"{n}={nrep[n]}" for n in names)
    fig.suptitle(f"CyberSwarm — 4 learning methods vs. fine-tuned defender (repeats: {reps_note})",
                 fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    out = "ft_comparison.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"wrote {out}\n")

    hdr = f"{'method':<12}{'repeats':>8}{'block% (mean)':>15}{'block_step':>12}{'patch_step':>12}{'mean_det':>10}"
    print(hdr); print("-" * len(hdr))
    for n in names:
        br_m = ms([r["block_rate"] for r in data[n]])[0]
        bs_m = ms([r["avg_block_step"] for r in data[n]])[0]
        ps_m = ms([r["avg_patch_step"] for r in data[n]])[0]
        dt_m = ms([r["mean_det"] for r in data[n]])[0]
        rates = "/".join(f"{r['block_rate']:.0f}" for r in data[n])
        print(f"{n:<12}{nrep[n]:>8}{br_m:>10.0f}% ({rates}){bs_m:>12.2f}{ps_m:>12.2f}{dt_m:>10.2f}")


if __name__ == "__main__":
    main()
