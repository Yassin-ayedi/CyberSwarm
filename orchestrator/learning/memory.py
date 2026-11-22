"""
memory.py — episodic memory. Stores each round's trajectory and a short summary, and builds
the context block injected into the next round's prompt (playbook + last N summaries).
"""
import os
import json


def playbook_path(run_dir, agent):
    return os.path.join(run_dir, f"playbook_{agent}.md")


def save_episode(run_dir, rnd, agent, transcript, summary):
    d = os.path.join(run_dir, f"round_{rnd}")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"{agent}_trajectory.json"), "w", encoding="utf-8") as f:
        json.dump(transcript, f, indent=2)
    with open(os.path.join(d, f"{agent}_summary.txt"), "w", encoding="utf-8") as f:
        f.write(summary)


def build_context(run_dir, agent, current_round, window, enable_memory):
    """Playbook + summaries of the last `window` rounds, as one prompt string."""
    if not enable_memory:
        return ""
    parts = []
    pb = playbook_path(run_dir, agent)
    if os.path.exists(pb):
        parts.append("YOUR PLAYBOOK (lessons from past rounds):\n" + open(pb, encoding="utf-8").read())
    summaries = []
    for r in range(max(0, current_round - window), current_round):
        p = os.path.join(run_dir, f"round_{r}", f"{agent}_summary.txt")
        if os.path.exists(p):
            summaries.append(f"Round {r}: " + open(p, encoding="utf-8").read().strip())
    if summaries:
        parts.append("RECENT EPISODES:\n" + "\n".join(summaries))
    return "\n\n".join(parts)


def summarize_transcript(transcript):
    """Cheap extractive summary (no LLM call needed for the MVP)."""
    tools = [t["tool"] for t in transcript if t.get("tool")]
    return f"{len(tools)} tool calls: " + ", ".join(tools[:12]) if tools else "no actions taken"
