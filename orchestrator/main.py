"""
main.py — entry point. Runs an experiment: N rounds, saving per-round scores to runs/.

    python main.py --config ../config/experiment.yaml

Ctrl-C tears the lab down (kill switch). The LLM calls go out from here, on the host;
the lab containers have no internet.
"""
import os
import sys
import argparse
import json
import signal

import yaml
from openai import OpenAI

from referee import Referee


def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "..", "config", "experiment.yaml"))
    ap.add_argument("--no-lab", action="store_true", help="skip docker reset (reuse running lab / dry-run prompts)")
    ap.add_argument("--name", default=None, help="override run_name (e.g. for repeats: baseline_r2)")
    ap.add_argument("--model", default=None, help="override llm.planner and llm.reflector (e.g. qwen2.5:7b)")
    args = ap.parse_args()

    cfg = load_cfg(args.config)
    if args.name:
        cfg["run_name"] = args.name
    if args.model:
        cfg["llm"]["planner"] = args.model
        cfg["llm"]["reflector"] = args.model
    run_dir = os.path.join(os.path.dirname(__file__), "..", "runs", cfg["run_name"])
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "config_used.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f)

    client = OpenAI(base_url=cfg["llm"]["base_url"], api_key=cfg["llm"].get("api_key", "x"))
    ref = Referee(cfg, client, run_dir)

    def _kill(*_):
        print("\n[kill switch] tearing down lab...", flush=True)
        ref.kill()
        sys.exit(1)
    signal.signal(signal.SIGINT, _kill)

    curve = []
    for rnd in range(cfg["rounds"]):
        print(f"\n===== ROUND {rnd} =====", flush=True)
        if not args.no_lab:
            ref.reset_lab()
        scores = ref.run_round(rnd)
        curve.append({"round": rnd, **scores})

    with open(os.path.join(run_dir, "curve.json"), "w", encoding="utf-8") as f:
        json.dump(curve, f, indent=2)
    print(f"\nDone. Curve written to {run_dir}/curve.json", flush=True)
    if not args.no_lab:
        ref.kill()


if __name__ == "__main__":
    main()
