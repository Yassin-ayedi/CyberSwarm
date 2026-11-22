"""
TickAgent: an LLM agent that is called once per tick (not once per round).

Each call rebuilds a SHORT prompt: system prompt (+ playbook) + a compact log of the agent's
own recent actions + this tick's observation. Keeping it short matters: Ollama silently drops
the start of a conversation that exceeds the context window, which would delete the system
prompt mid-episode. Every exchange is also recorded (prompt + answer + outcome) so episodes
can later be turned into a fine-tuning dataset.
"""
import json
import re
import time


class TickAgent:
    def __init__(self, name, client, model, system, schemas, playbook="", temperature=0.3,
                 max_calls=1, history_len=8):
        self.name = name
        self.client = client
        self.model = model
        self.system = system + (f"\n\nYOUR PLAYBOOK (lessons you wrote after past episodes):\n{playbook}"
                                if playbook.strip() else "")
        self.schemas = schemas
        self.temperature = temperature
        self.max_calls = max_calls
        self.history = []          # short lines: what I did and what happened
        self.history_len = history_len
        self.records = []          # full exchanges, for datasets
        self._seen = set()

    def step(self, tick, observation, execute):
        """Run up to max_calls tool calls for this tick. execute(name, args) -> result text.
        Returns a list of {"tool","args","result"} or {"thought"} entries."""
        recent = "\n".join(self.history[-self.history_len:]) or "(nothing yet)"
        messages = [{"role": "system", "content": self.system},
                    {"role": "user", "content": f"Your recent actions and results:\n{recent}\n\n{observation}"}]
        out = []
        for _ in range(self.max_calls):
            resp, err = None, None
            for attempt in range(4):          # survive a short tunnel drop instead of losing the tick
                try:
                    resp = self.client.chat.completions.create(model=self.model, messages=messages,
                                                               tools=self.schemas, tool_choice="auto",
                                                               temperature=self.temperature)
                    break
                except Exception as e:
                    err = e
                    time.sleep(5 * (attempt + 1))
            if resp is None:
                out.append({"thought": f"[llm error: {str(err)[:120]}]"})
                break
            msg = resp.choices[0].message
            calls = _tool_calls(msg)
            if not calls:
                text = (msg.content or "").strip()
                out.append({"thought": text[:400]})
                self.history.append(f"t{tick}: (no action) {text[:100]}")
                break
            messages.append(_assistant_msg(msg, calls))
            stop = False
            for cid, fn, args in calls[:1]:          # one call at a time, react to the result
                key = fn + json.dumps(args, sort_keys=True)
                if key in self._seen and fn not in ("wait", "inspect_ip"):
                    result = "Not executed: you already did exactly this earlier; its result is in your history."
                else:
                    self._seen.add(key)
                    result = execute(fn, args)
                out.append({"tool": fn, "args": args, "result": str(result)[:600]})
                self.history.append(f"t{tick}: {fn}({_short(args)}) -> {_short(result, 160)}")
                messages.append({"role": "tool", "tool_call_id": cid, "content": str(result)[:3000]})
                stop = fn == "wait"
            self.records.append({"tick": tick, "messages": messages[:], "calls": [c[1:] for c in calls]})
            if stop:
                break
        return out


def _tool_calls(msg):
    calls = []
    for tc in (msg.tool_calls or []):
        try:
            args = json.loads(tc.function.arguments or "{}")
        except json.JSONDecodeError:
            args = {}
        calls.append((tc.id, tc.function.name, args if isinstance(args, dict) else {}))
    if not calls and msg.content:
        # some models print the call as JSON text instead of using the tool channel
        m = re.search(r'\{\s*"name"\s*:\s*"(\w+)"\s*,\s*"arguments"\s*:\s*(\{.*\})\s*\}', msg.content, re.S)
        if m:
            try:
                calls.append(("text_call", m.group(1), json.loads(m.group(2))))
            except json.JSONDecodeError:
                pass
    return calls


def _assistant_msg(msg, calls):
    return {"role": "assistant", "content": msg.content or "",
            "tool_calls": [{"id": cid, "type": "function",
                            "function": {"name": fn, "arguments": json.dumps(args)}} for cid, fn, args in calls]}


def _short(x, n=90):
    s = json.dumps(x) if isinstance(x, dict) else str(x)
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "..."
