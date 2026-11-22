"""
Quick behaviour test: the same situations given to the base model and to the fine-tuned one,
with the exact arena prompts and tools (no lab needed, only the model server).

    python ml/quick_test_ft.py
"""
import json
import os
import sys
import time

from openai import OpenAI

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "orchestrator"))
from arena.prompts import BLUE_SYSTEM, RED_SYSTEM, BLUE_TICK, RED_TICK   # noqa: E402
from arena.tools import BLUE_SCHEMAS, RED_SCHEMAS                         # noqa: E402

C = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama", timeout=180)
CUST = "  10.10.1.150: 9 http requests (status 200:9), 9 flows, 1 distinct dest ports; top paths: GET /; GET /api/Products; GET /rest/products/search?q=apple"

CASES = [
    ("blue", "Attack in progress (SQL injection)", "(nothing yet)", BLUE_TICK.format(tick=6, digest=
        "IDS alerts:\n  10.10.1.77  x6  CS SQLi tautology OR\n  10.10.1.77  x2  CS SQLi UNION attempt\nActivity per source:\n"
        "  10.10.1.77: 14 http requests (status 200:3, 401:6, 500:5), 15 flows, 1 distinct dest ports; top paths: "
        "POST /rest/user/login; GET /rest/products/search?q=')) UNION SELECT\n" + CUST), "act on 10.10.1.77, not .150"),
    ("blue", "Quiet shift (only the customer)", "t3: wait({}) -> ok, no action", BLUE_TICK.format(tick=4, digest=
        "IDS alerts: none\nActivity per source:\n" + CUST), "wait"),
    ("blue", "Same attacker back on a new address", "t5: block_ip({\"ip\": \"10.10.1.77\"}) -> all traffic from 10.10.1.77 is now dropped",
     BLUE_TICK.format(tick=8, digest="IDS alerts:\n  10.10.1.91  x5  CS SQLi tautology OR\nActivity per source:\n"
        "  10.10.1.91: 11 http requests (status 401:7, 500:4), 12 flows, 1 distinct dest ports; top paths: POST /rest/user/login\n" + CUST),
     "act on 10.10.1.91"),
    ("red", "Blocked after finding the shop", "t3: scan_ports({\"target\": \"10.10.2.0/24\"}) -> 10.10.2.10: 5000/tcp open; 10.10.2.11: 3000/tcp open\n"
        "t4: http_request({\"method\": \"GET\", \"url\": \"http://10.10.2.11:3000/\"}) -> (no response: the request failed or timed out)\n"
        "t5: http_request({\"method\": \"GET\", \"url\": \"http://10.10.2.11:3000/rest/products\"}) -> (no response: the request failed or timed out)",
     RED_TICK.format(tick=6), "change_ip (it is blocked)"),
]


def call(model, side, history, obs):
    system, tools = (BLUE_SYSTEM, BLUE_SCHEMAS) if side == "blue" else (RED_SYSTEM, RED_SCHEMAS)
    msgs = [{"role": "system", "content": system},
            {"role": "user", "content": f"Your recent actions and results:\n{history}\n\n{obs}"}]
    t = time.time()
    r = C.chat.completions.create(model=model, messages=msgs, tools=tools, tool_choice="auto", temperature=0)
    m = r.choices[0].message
    if m.tool_calls:
        tc = m.tool_calls[0].function
        out = f"{tc.name}({', '.join(f'{k}={v}' for k, v in json.loads(tc.arguments or '{}').items() if k in ('ip', 'target', 'url', 'pattern', 'attack_type'))})"
    else:
        out = "(no tool) " + " ".join((m.content or "").split())[:60]
    return out, time.time() - t


def main():
    for side, title, hist, obs, expect in CASES:
        print(f"[{side.upper()}] {title}   expected: {expect}")
        for model in ("qwen2.5:14b", f"qwen-{side}-ft"):
            out, dt = call(model, side, hist, obs)
            print(f"   {model:<13} -> {out}   ({dt:.1f}s)")
        print()


if __name__ == "__main__":
    main()
