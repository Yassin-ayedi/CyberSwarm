"""
plot_curves.py — turn runs/<run>/curve.json into the figures for the report, and build the
E2 ablation table (learning vs no-learning, etc.).

    python plot_curves.py ../runs/baseline ../runs/no_learning

Produces two panels: Red's challenges-solved per round (the real offensive metric from
Juice Shop's scoreboard) and Blue's per-round detections, overlaid across runs.
"""
import sys
import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load(run_dir):
    with open(os.path.join(run_dir, "curve.json"), encoding="utf-8") as f:
        return json.load(f)


def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def main(run_dirs):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))
    table = []
    for rd in run_dirs:
        curve = load(rd)
        name = os.path.basename(rd.rstrip("/\\"))
        rounds = [c["round"] for c in curve]
        solved = [c.get("challenges_solved_round", 0) for c in curve]
        detections = [c.get("detections", 0) for c in curve]
        ax1.plot(rounds, solved, marker="o", label=name)
        ax2.plot(rounds, detections, marker="s", label=name)
        table.append((name, solved, detections,
                      curve[-1]["red_score"], curve[-1]["blue_score"]))

    ax1.set_title("Red: challenges solved / round"); ax1.set_xlabel("Round")
    ax1.set_ylabel("challenges solved"); ax1.grid(True, alpha=0.3); ax1.legend()
    ax2.set_title("Blue: detections / round"); ax2.set_xlabel("Round")
    ax2.set_ylabel("IDS alerts"); ax2.grid(True, alpha=0.3); ax2.legend()
    fig.suptitle("CyberSwarm — learning vs no-learning (E2 ablation)")
    out = "learning_curves.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"wrote {out}")

    print("\nAblation table (E2):")
    hdr = f"{'config':<14}{'solved/round':>26}{'mean_solved':>12}{'mean_det':>10}{'Red_fin':>9}{'Blue_fin':>9}"
    print(hdr)
    for name, solved, det, rfin, bfin in table:
        seq = ",".join(str(s) for s in solved)
        print(f"{name:<14}{seq:>26}{mean(solved):>12.2f}{mean(det):>10.2f}{rfin:>9}{bfin:>9}")


if __name__ == "__main__":
    dirs = sys.argv[1:] or ["../runs/baseline"]
    main(dirs)
