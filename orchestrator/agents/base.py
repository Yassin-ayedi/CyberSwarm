"""
base.py — the generic LLM tool-use loop shared by Red and Blue.
observe -> reason -> tool call -> observe, until step budget or a stop condition.

Uses the OpenAI-compatible client, so it works against Ollama or vLLM unchanged
(base_url + model from experiment.yaml). Tool calling is native (tools=SCHEMAS).
"""
import json
from openai import OpenAI


class Agent:
    def __init__(self, name, client: OpenAI, model, system_prompt, schemas, toolset, max_steps=8):
        self.name = name
        self.client = client
        self.model = model
        self.schemas = schemas
        self.toolset = toolset           # object with .call(name, **kwargs)
        self.messages = [{"role": "system", "content": system_prompt}]
        self.max_steps = max_steps

    def add_context(self, text):
        """Inject playbook / memory / debrief into the conversation before the round."""
        self.messages.append({"role": "user", "content": text})

    def run(self, opening_user_msg, on_step=None):
        self.messages.append({"role": "user", "content": opening_user_msg})
        transcript = []
        seen_calls = {}   # (tool, args) -> count : stagnation guard (ARTEX detectStagnation idea)
        tool_counts = {}  # tool -> total calls this round
        for step in range(self.max_steps):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.messages,
                    tools=self.schemas,
                    tool_choice="auto",
                    temperature=0.3,
                )
            except Exception as e:
                # A single bad generation (e.g. Ollama "token repeat limit reached", a
                # timeout, or a 500) must not crash a multi-hour run. End this agent's turn
                # gracefully and let the round/experiment continue.
                transcript.append({"step": step, "error": str(e)[:200]})
                if on_step:
                    on_step(self.name, step, None, f"[llm error, ending turn: {str(e)[:100]}]")
                break
            msg = resp.choices[0].message
            self.messages.append(msg.model_dump(exclude_none=True))

            if not msg.tool_calls:
                # model answered in prose: record and stop (it decided it's done)
                transcript.append({"step": step, "thought": msg.content})
                if on_step:
                    on_step(self.name, step, None, msg.content)
                break

            for tc in msg.tool_calls:
                fn = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}

                # --- stagnation guard (adapted from ARTEX detectStagnation) ---
                # An exact repeat of a prior call produces no new information: don't
                # re-execute it, nudge the model to advance instead. Also nudge once a
                # single tool dominates the round. This is what stops the model looping
                # one tool (e.g. scan_ports x8) instead of walking the kill chain.
                key = (fn, json.dumps(args, sort_keys=True))
                seen_calls[key] = seen_calls.get(key, 0) + 1
                tool_counts[fn] = tool_counts.get(fn, 0) + 1

                if seen_calls[key] > 1:
                    nudge = (f"BLOCKED: you already called {fn} with these exact arguments; "
                             f"its result is above. Repeating it is wasted. Advance the kill "
                             f"chain now — move to the next phase (enumerate endpoints, then "
                             f"attempt the SQL-injection login, then extract the flag). Do NOT "
                             f"repeat a tool you have already run.")
                    transcript.append({"step": step, "tool": fn, "args": args, "result": "[blocked: duplicate]"})
                    if on_step:
                        on_step(self.name, step, fn, "[blocked: duplicate call]")
                    self.messages.append({"role": "tool", "tool_call_id": tc.id,
                                          "content": json.dumps({"ok": False, "summary": nudge})})
                    continue

                result = self.toolset.call(fn, **args)
                summary = result["summary"]
                if tool_counts[fn] >= 3:
                    summary += (f"\n\n[hint: you have used {fn} {tool_counts[fn]} times this round. "
                                f"If it is not advancing you toward the flag, switch technique or "
                                f"move to the next phase.]")
                transcript.append({"step": step, "tool": fn, "args": args, "result": summary[:300]})
                if on_step:
                    on_step(self.name, step, fn, summary[:200])
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps({"ok": result["ok"], "summary": summary})[:4000],
                })
        return transcript
