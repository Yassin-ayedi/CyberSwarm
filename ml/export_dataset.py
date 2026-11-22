"""Export collected agent trajectories into an SFT dataset for fine-tuning (Block 4).

Walks runs/<run>/round_*/{red,blue}_messages.json + scores.json, keeps only SUCCESSFUL
episodes (behavioural cloning of good behaviour), and writes ml/dataset.jsonl with one
record per kept agent-round: {agent, run, round, messages, tools}. train_qlora.py on the
GPU VM renders each record with the model's chat template (tools included) and trains.

    python export_dataset.py            # all runs
"""
import json, os, glob, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUNS = os.path.join(ROOT, "runs")
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))
from tools.red_tools import SCHEMAS as RED_SCHEMAS       # noqa: E402
from tools.blue_tools import SCHEMAS as BLUE_SCHEMAS     # noqa: E402
SCHEMAS = {"red": RED_SCHEMAS, "blue": BLUE_SCHEMAS}


def red_success(sc):
    """Red episode worth cloning: it solved at least one challenge (or took the flag)."""
    return sc.get("challenges_solved_round", 0) > 0 or sc.get("flag_captured", False)


def blue_success(sc):
    """Blue episode worth cloning: it detected the attack and blocked no legitimate users."""
    return sc.get("detections", 0) > 0 and sc.get("legit_blocked", 0) == 0


def main():
    out_path = os.path.join(ROOT, "ml", "dataset.jsonl")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    counts = {"red": 0, "blue": 0}
    with open(out_path, "w", encoding="utf-8") as out:
        for rd in sorted(glob.glob(os.path.join(RUNS, "*", "round_*"))):
            sp = os.path.join(rd, "scores.json")
            if not os.path.exists(sp):
                continue
            try:
                sc = json.load(open(sp, encoding="utf-8"))
            except Exception:
                continue
            run = os.path.basename(os.path.dirname(rd))
            rnd = os.path.basename(rd)
            for agent, ok in (("red", red_success(sc)), ("blue", blue_success(sc))):
                if not ok:
                    continue
                mp = os.path.join(rd, f"{agent}_messages.json")
                if not os.path.exists(mp):
                    continue
                try:
                    msgs = json.load(open(mp, encoding="utf-8"))
                except Exception:
                    continue
                if not msgs or len(msgs) < 3:   # need at least system+user+one action
                    continue
                out.write(json.dumps({"agent": agent, "run": run, "round": rnd,
                                      "messages": msgs, "tools": SCHEMAS[agent]}) + "\n")
                counts[agent] += 1
    print(f"wrote {out_path}: {counts['red'] + counts['blue']} examples "
          f"(red={counts['red']}, blue={counts['blue']})")


if __name__ == "__main__":
    main()
