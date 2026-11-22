"""
debrief.py — the cross-agent exchange that is the project's central claim. After a round,
Red is shown Blue's alerts/actions and Blue is shown Red's action log. Each then reflects
WITH that extra information. Ablating this flag (learning.debrief) is experiment E2.
"""


def red_sees(blue_action_log):
    """What Blue did, from Red's point of view: which of Red's moves got noticed/blocked."""
    if not blue_action_log:
        return "The defender took no visible action."
    lines = ["The defender did the following (this is what gave you away / stopped you):"]
    for a in blue_action_log:
        lines.append(f"- {a['tool']}({a.get('args')}) [{a['status']}]")
    return "\n".join(lines)


def blue_sees(red_action_log):
    """Red's ground-truth actions, revealed to Blue so it can learn what it missed."""
    if not red_action_log:
        return "The attacker took no action."
    lines = ["The attacker actually did the following (ground truth — note what your sensors missed):"]
    for a in red_action_log:
        lines.append(f"- {a['tool']}({a.get('args')}) [{a['status']}]")
    return "\n".join(lines)
