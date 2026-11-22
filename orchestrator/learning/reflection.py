"""
reflection.py — one LLM call at round end. Each agent extracts a few durable lessons from
its own trajectory (and, when debrief is on, from the other side's log). Lessons are
appended to playbook_<agent>.md, deduplicated and length-capped.
"""
import os

# Role framing keeps each side's lessons IN-ROLE. Without this, a small reflector model
# drifts: it wrote defender advice ("use parameterised queries", "avoid /metrics") into the
# ATTACKER's playbook, which made Red progressively more timid and solve fewer challenges.
ROLE_FRAMING = {
    "red": (
        "You are RED, the attacker. Your lessons must make you a MORE EFFECTIVE ATTACKER next "
        "round: exploits that worked and how to repeat/extend them, payloads to fix, new "
        "endpoints to hit, how to evade the defender. NEVER write defensive advice (patching, "
        "input validation, avoiding endpoints, 'use parameterised queries') — that is the "
        "defender's job and it is wrong for you. If the defender blocked you, note how to act "
        "faster or from where, not how to behave."
    ),
    "blue": (
        "You are BLUE, the defender. Your lessons must make you a MORE EFFECTIVE DEFENDER next "
        "round: detect the attack sooner, block the attacker's IP (not legitimate users at "
        "10.10.1.20), write better detections. NEVER write attacker advice."
    ),
}

REFLECT_PROMPT = """{role}

You just finished a round in the security lab. Here is what happened.

YOUR ACTIONS AND RESULTS:
{own}

{debrief_block}

Write 1-3 short, concrete, reusable lessons that fit YOUR ROLE above, for next round. Each
lesson is one line, imperative, specific (name the tool, port, endpoint or technique). No
preamble, no numbering. Only lessons that would change what you do next time."""


def reflect(client, model, agent_name, own_transcript, debrief_text, playbook_path, max_lessons=3):
    debrief_block = f"WHAT THE OTHER SIDE DID (debrief):\n{debrief_text}" if debrief_text else ""
    own = "\n".join(_fmt(t) for t in own_transcript) or "(no actions)"
    role = ROLE_FRAMING.get(agent_name, "")
    prompt = REFLECT_PROMPT.format(role=role, own=own, debrief_block=debrief_block)
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.4,
    )
    lessons = [l.strip("-• \t") for l in resp.choices[0].message.content.splitlines() if l.strip()]
    lessons = lessons[:max_lessons]
    _append_dedup(playbook_path, lessons)
    return lessons


def _fmt(t):
    if t.get("tool"):
        return f"- {t['tool']}({t.get('args')}) -> {t.get('result','')}"
    return f"- thought: {t.get('thought','')}"


def _append_dedup(path, lessons, cap=40):
    existing = []
    if os.path.exists(path):
        existing = [l.rstrip() for l in open(path, encoding="utf-8").read().splitlines() if l.strip()]
    existing_set = {l.lower() for l in existing}
    for l in lessons:
        if l.lower() not in existing_set:
            existing.append(f"- {l}")
            existing_set.add(l.lower())
    existing = existing[-cap:]   # keep the playbook bounded
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(existing) + "\n")
