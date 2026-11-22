"""
Build fine-tuning datasets for Blue and Red from arena TRAINING episodes (never the held-out
test phases). Filtered behaviour cloning: only decisions that were good, judged from the
ground truth recorded in each episode, are kept.

Blue keeps:  actions on a real attacker address (inspect / incident / block / rate-limit),
             WAF patterns during an attack, and "wait" when there was nothing to do (no attack
             yet, quiet shift, or the attacker's current address already blocked).
Blue drops:  any action on an innocent address (false alarm), waiting while the attacker was
             active and unblocked, duplicate calls.
Red keeps:   actions that produced information (open ports, HTTP answers other than 404,
             sqlmap/gobuster findings) and successful address changes.
Red drops:   dead ends (no answer, 404, refused, blocked), duplicates.

    python ml/export_arena_dataset.py --runs mvp1 mvp2 --out ml/arena_data
Each line: {"messages": [...], "tools": [...]}; the last message is the assistant turn to learn.
"""
import argparse
import glob
import json
import os
import random
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))
from arena.tools import RED_SCHEMAS, BLUE_SCHEMAS   # noqa: E402

GOOD_RED = re.compile(r"\d+/tcp\s+open\b|HTTP/[12](?:\.[01])? (?!404)\d{3}|Status: \d{3}|available databases|"
                      r"is vulnerable|Parameter: |back-end DBMS|Your source address is now")


def as_dict_args(msg):
    """Qwen's chat template wants tool-call arguments as a dict, not a JSON string."""
    m = dict(msg)
    if m.get("tool_calls"):
        calls = []
        for c in m["tool_calls"]:
            f = dict(c["function"])
            if isinstance(f.get("arguments"), str):
                try:
                    f["arguments"] = json.loads(f["arguments"] or "{}")
                except json.JSONDecodeError:
                    f["arguments"] = {}
            calls.append({"type": "function", "function": f})
        m["tool_calls"] = calls
    if m.get("content") is None:
        m["content"] = ""
    return m


def example(record):
    """Prompt + the LAST assistant turn of this record (drop the trailing tool result)."""
    msgs = record["messages"]
    last = max(i for i, m in enumerate(msgs) if m["role"] == "assistant")
    return [as_dict_args(m) for m in msgs[:last + 1]], (msgs[last + 1]["content"] if last + 1 < len(msgs) else "")


def blue_label(rec, ep):
    s, r = ep["scenario"], ep.get("result", {})
    if not rec["calls"]:
        return None
    name, args = rec["calls"][0]
    atk_ips = r.get("attacker_ips") or ([s["attacker_ip"]] if s["attack"] else [])
    tick = next((t for t in ep["ticks"] if t["tick"] == rec["tick"]), None)
    if tick is None:
        return None
    cur = tick.get("attacker_ip") or s["attacker_ip"]
    active = s["attack"] and rec["tick"] >= s["red_start_tick"]
    if name in ("inspect_ip", "raise_alert", "block_ip", "rate_limit", "unblock_ip"):
        ip = str(args.get("ip", ""))
        if name == "unblock_ip":
            return "good" if ip not in atk_ips else None          # undoing a block on an innocent is good
        return "good" if ip in atk_ips else None
    if name in ("block_pattern", "add_ids_rule"):
        return "good" if active else None
    if name == "wait":
        calm = (not active) or (cur in tick["firewall"])
        return "wait" if calm else None
    return None


def red_label(rec, result_text):
    if not rec["calls"] or result_text.startswith("Not executed"):
        return None
    return "good" if GOOD_RED.search(result_text or "") else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", default=["mvp1", "mvp2"])
    ap.add_argument("--out", default=os.path.join(ROOT, "ml", "arena_data"))
    ap.add_argument("--max_wait_share", type=float, default=0.35)
    a = ap.parse_args()
    rng = random.Random(0)
    data = {"blue": {"good": [], "wait": []}, "red": {"good": []}}
    stats = {"blue_seen": 0, "red_seen": 0}
    for run in a.runs:
        for xf in sorted(glob.glob(os.path.join(ROOT, "runs", "arena", run, "train", "ep_*_exchanges.jsonl"))):
            ep = json.load(open(xf.replace("_exchanges.jsonl", ".json"), encoding="utf-8"))
            if ep.get("status") != "done":
                continue
            for line in open(xf, encoding="utf-8"):
                rec = json.loads(line)
                msgs, result = example(rec)
                if rec["side"] == "blue":
                    stats["blue_seen"] += 1
                    lab = blue_label(rec, ep)
                    if lab:
                        data["blue"][lab].append({"messages": msgs, "tools": BLUE_SCHEMAS, "src": f"{run}/{os.path.basename(xf)}"})
                else:
                    stats["red_seen"] += 1
                    if red_label(rec, result):
                        data["red"]["good"].append({"messages": msgs, "tools": RED_SCHEMAS, "src": f"{run}/{os.path.basename(xf)}"})
    good, waits = data["blue"]["good"], data["blue"]["wait"]
    cap = int(a.max_wait_share / (1 - a.max_wait_share) * len(good))
    rng.shuffle(waits)
    blue = good + waits[:cap]
    rng.shuffle(blue)
    red = data["red"]["good"]
    rng.shuffle(red)
    os.makedirs(a.out, exist_ok=True)
    for side, rows in (("blue", blue), ("red", red)):
        with open(os.path.join(a.out, f"{side}.jsonl"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"Blue: {stats['blue_seen']} decisions seen -> {len(good)} good actions + {min(cap, len(waits))} calm waits "
          f"(of {len(waits)}) = {len(blue)} examples")
    print(f"Red:  {stats['red_seen']} decisions seen -> {len(red)} useful actions kept")
    from collections import Counter
    print("Blue tools:", dict(Counter(r["messages"][-1]["tool_calls"][0]["function"]["name"] for r in blue)))
    print("Red tools: ", dict(Counter(r["messages"][-1]["tool_calls"][0]["function"]["name"] for r in red)))


if __name__ == "__main__":
    main()
