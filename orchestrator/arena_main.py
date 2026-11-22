"""
arena_main.py: run the CyberSwarm arena (MVP co-evolution mode).

  # training: LLM Red vs LLM Blue, both write lessons to their playbooks after each episode
  python arena_main.py train --run mvp1 --episodes 8

  # held-out test: scripted attacks Blue never trained against (no learning during eval)
  python arena_main.py eval --run mvp1 --attackers scripted --episodes 8            # trained Blue
  python arena_main.py eval --run mvp1 --attackers scripted --episodes 8 --untrained # same seeds, empty playbook

  # add --fake to any command to use the simulated lab + fake model (no Docker, no GPU)

Outputs go to runs/arena/<run>/<phase>/ and are listed in runs/arena/index.json for the
dashboard (python -m http.server 8000, then open http://localhost:8000/dashboard/).
"""
import argparse
import json
import os
import sys
import time

import yaml

sys.path.insert(0, os.path.dirname(__file__))
from arena import scenario as scen                      # noqa: E402
from arena.agents import TickAgent                       # noqa: E402
from arena.match import run_episode, reflect             # noqa: E402
from arena.prompts import RED_SYSTEM, BLUE_SYSTEM        # noqa: E402
from arena.tools import RED_SCHEMAS, BLUE_SCHEMAS        # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUNS = os.path.join(ROOT, "runs", "arena")


def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def read(path):
    return open(path, encoding="utf-8").read() if os.path.exists(path) else ""


def update_index(run, phase, info):
    os.makedirs(RUNS, exist_ok=True)
    p = os.path.join(RUNS, "index.json")
    idx = json.loads(read(p) or "{}")
    idx.setdefault(run, {})[phase] = info
    with open(p, "w", encoding="utf-8") as f:
        json.dump(idx, f, indent=1)


def tick_printer(scn, tick):
    red = "; ".join(f"{r['tool']}{'' if r.get('reached') else ' (no answer)'}" for r in tick["red"] if r.get("tool"))
    blue = "; ".join(f"{b['tool']}({b.get('args', {}).get('ip', '')})" if b.get("tool") else "think"
                     for b in tick["blue"])
    al = sum(a["count"] for a in tick["alerts"])
    print(f"  t{tick['tick']:02d} red[{red or '-'}] alerts={al} blue[{blue or '-'}] "
          f"legit ok/fail={tick['legit']['ok']}/{tick['legit']['fail']}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["train", "eval"])
    ap.add_argument("--run", required=True)
    ap.add_argument("--episodes", type=int, default=6)
    ap.add_argument("--start", type=int, default=0, help="first episode index (to resume)")
    ap.add_argument("--attackers", choices=["llm", "scripted"], default="scripted", help="eval only")
    ap.add_argument("--untrained", action="store_true", help="eval with an empty Blue playbook")
    ap.add_argument("--no-learn", action="store_true", help="train without reflection (control)")
    ap.add_argument("--ticks", type=int, default=None)
    ap.add_argument("--blue-model", default=None, help="override the defender model (e.g. qwen-blue-ft)")
    ap.add_argument("--red-model", default=None, help="override the attacker model (e.g. qwen-red-ft)")
    ap.add_argument("--label", default=None, help="eval phase label instead of trained/untrained (e.g. finetuned)")
    ap.add_argument("--fake", action="store_true", help="simulated lab + fake model")
    ap.add_argument("--config", default=os.path.join(ROOT, "config", "arena.yaml"))
    a = ap.parse_args()
    cfg = load_cfg(a.config)
    E, L = cfg["episode"], cfg["llm"]
    if a.blue_model:
        L["blue_model"] = a.blue_model
    if a.red_model:
        L["red_model"] = a.red_model
    ticks = a.ticks or E["ticks"]

    if a.fake:
        from arena.fakelab import FakeLab
        from arena.fakellm import FakeLLM
        lab, client = FakeLab(seed=1), FakeLLM(seed=1)
    else:
        from openai import OpenAI
        from arena.lab import LiveLab
        lab = LiveLab()
        lab.check()
        client = OpenAI(base_url=L["base_url"], api_key=L.get("api_key", "x"), timeout=L.get("timeout_s", 120))

    run_dir = os.path.join(RUNS, a.run)
    pb_blue, pb_red = os.path.join(run_dir, "playbook_blue.md"), os.path.join(run_dir, "playbook_red.md")
    if a.mode == "train":
        phase = "train" + ("_nolearn" if a.no_learn else "")
    else:
        phase = f"eval_{a.attackers}_{a.label or ('untrained' if a.untrained else 'trained')}"
    out_dir = os.path.join(run_dir, phase)
    os.makedirs(out_dir, exist_ok=True)
    summary_path = os.path.join(out_dir, "summary.json")
    summary = json.loads(read(summary_path) or "[]") if a.start else []

    for i in range(a.start, a.start + a.episodes):
        if a.mode == "train":
            s = scen.make(cfg["seeds"]["train_base"] + i, ticks, "llm", E["quiet_prob"], E["red_act_prob"])
        else:
            kind = "llm" if a.attackers == "llm" else scen.SCRIPTED[i % len(scen.SCRIPTED)]
            s = scen.make(cfg["seeds"]["eval_base"] + i, ticks, kind, E["quiet_prob"], E["red_act_prob"])
        blue_pb = "" if a.untrained else read(pb_blue)
        blue = TickAgent("blue", client, L["blue_model"], BLUE_SYSTEM, BLUE_SCHEMAS, blue_pb,
                         L["temperature"], max_calls=E["blue_calls_per_tick"])
        red = TickAgent("red", client, L["red_model"], RED_SYSTEM, RED_SCHEMAS, read(pb_red),
                        L["temperature"], max_calls=E.get("red_calls_per_tick", 1))
        print(f"\n=== {phase} episode {i}: attack={s.attack} attacker={s.attacker} "
              f"start=t{s.red_start_tick} ticks={s.n_ticks} ===", flush=True)
        ep_path = os.path.join(out_dir, f"ep_{i:03d}.json")
        meta = {"run": a.run, "phase": phase, "episode": i, "lab": lab.name,
                "blue_playbook": blue_pb, "red_playbook": read(pb_red), "started": time.strftime("%Y-%m-%d %H:%M:%S"),
                "blue_model": L["blue_model"], "red_model": L["red_model"]}
        update_index(a.run, phase, {"episodes": len(summary) + 1, "live": f"ep_{i:03d}.json"})
        ep = run_episode(lab, s, blue, red, ep_path, meta, tick_printer,
                         end_when_shut_out=E.get("end_when_shut_out", 2))
        if ep.get("ended_early"):
            print(f"  (ended early at t{ep['ended_early']['tick']}: {ep['ended_early']['reason']})", flush=True)
        res = ep["result"]
        print(f"  -> detected={res['detected']} ttd={res['time_to_detect']} contained={res['contained']} "
              f"ttc={res['time_to_contain']} solves={len(res['challenges_solved'])} fp={res['false_positive_actions']} "
              f"avail={res['availability']} | blue={res['blue_reward']} red={res['red_reward']}", flush=True)

        if a.mode == "train" and not a.no_learn:
            lb = reflect(client, L["reflector"], "blue", ep, pb_blue)
            lr = reflect(client, L["reflector"], "red", ep, pb_red) if s.attack else []
            ep["lessons"] = {"blue": lb, "red": lr}
            with open(ep_path, "w", encoding="utf-8") as f:
                json.dump(ep, f, indent=1, default=str)
            for l in lb:
                print(f"  blue learned: {l}", flush=True)
            for l in lr:
                print(f"  red learned:  {l}", flush=True)
        # full exchanges (prompt + answer) for a future fine-tuning dataset
        with open(os.path.join(out_dir, f"ep_{i:03d}_exchanges.jsonl"), "w", encoding="utf-8") as f:
            for side, ag in (("blue", blue), ("red", red)):
                for r in ag.records:
                    f.write(json.dumps({"side": side, **r}, default=str) + "\n")
        summary.append({"episode": i, "file": f"ep_{i:03d}.json", "scenario": s.to_dict(),
                        "ticks_played": len(ep["ticks"]), "ended_early": ep.get("ended_early"), **res})
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=1)
        update_index(a.run, phase, {"episodes": len(summary), "live": None})
    print(f"\nDone: {out_dir}", flush=True)


if __name__ == "__main__":
    main()
