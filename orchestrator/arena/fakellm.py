"""
FakeLLM: stands in for the OpenAI/Ollama client in dry-run mode. It mimics
client.chat.completions.create(...) with simple rule-based players so the whole pipeline can
be exercised without a GPU. Its "learning" is a toy: a Blue playbook mentioning behaviour
makes it also react to sources with many failed requests (no signature needed).
"""
import json
import random
import re
import uuid


class _Fn:
    def __init__(self, name, args):
        self.name, self.arguments = name, json.dumps(args)


class _Call:
    def __init__(self, name, args):
        self.id, self.type, self.function = "call_" + uuid.uuid4().hex[:8], "function", _Fn(name, args)


class _Msg:
    def __init__(self, content=None, calls=None):
        self.content, self.tool_calls, self.role = content, calls, "assistant"

    def model_dump(self, **_):
        return {"role": "assistant", "content": self.content}


class _Resp:
    def __init__(self, msg):
        self.choices = [type("C", (), {"message": msg})()]


class FakeLLM:
    def __init__(self, seed=0):
        self.rng = random.Random(seed)
        self.chat = type("Chat", (), {})()
        self.chat.completions = type("Comp", (), {"create": self.create})()

    def create(self, model=None, messages=None, tools=None, **_):
        system = messages[0]["content"] if messages[0]["role"] == "system" else ""
        if not tools:            # reflection call
            role = "blue" if "BLUE" in messages[-1]["content"] else "red"
            lessons = {
                "blue": ["Treat one source producing many 401/404 errors as an attack even without IDS alerts",
                         "Raise an alert and block within one tick once a source shows SQL payloads"],
                "red": ["Start with a port scan, then probe the login endpoint with an injection",
                        "Spread requests out to stay under the scan threshold"],
            }[role]
            return _Resp(_Msg("\n".join(self.rng.sample(lessons, k=len(lessons)))))
        if "You are BLUE" in system:
            return _Resp(self._blue(system, messages))
        return _Resp(self._red())

    def _red(self):
        choice = self.rng.random()
        if choice < 0.2:
            return _Msg(calls=[_Call("scan_ports", {"target": "10.10.2.11"})])
        if choice < 0.6:
            return _Msg(calls=[_Call("http_request", {"method": "POST", "url": "http://10.10.2.11:3000/rest/user/login",
                                                      "body": json.dumps({"email": "' or 1=1--", "password": "x"})})])
        if choice < 0.8:
            return _Msg(calls=[_Call("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/metrics"})])
        return _Msg(calls=[_Call("run_command", {"command": "gobuster dir -u http://10.10.2.11:3000 -w $WORDLIST -q"})])

    def _blue(self, system, messages):
        obs = messages[1]["content"]
        last = messages[-1]
        blocked = set(re.findall(r"block_ip\(\{\"ip\": \"([\d.]+)\"", obs))
        suspects = {}
        for ip, n in re.findall(r"^\s+(10\.10\.1\.\d+)\s+x(\d+)\s", obs, re.M):
            suspects[ip] = suspects.get(ip, 0) + int(n)
        if "401" in system or "404" in system:          # learned behaviour rule from playbook
            for ip, codes in re.findall(r"^\s+(10\.10\.1\.\d+): \d+ http requests \(status ([^)]*)\)", obs, re.M):
                bad = sum(int(n) for c, n in re.findall(r"(40[134]|500):(\d+)", codes))
                if bad >= 3:
                    suspects[ip] = suspects.get(ip, 0) + bad
        suspects = {ip: n for ip, n in suspects.items() if ip not in blocked}
        if last["role"] == "tool":
            prev = messages[-2]["tool_calls"][0]["function"]
            if prev["name"] == "raise_alert":
                return _Msg(calls=[_Call("block_ip", {"ip": json.loads(prev["arguments"])["ip"]})])
            return _Msg(calls=[_Call("wait", {"reason": "contained"})])
        if suspects and self.rng.random() < 0.85:
            ip = max(suspects, key=suspects.get)
            return _Msg(calls=[_Call("raise_alert", {"ip": ip, "attack_type": "web attack", "evidence": "alerts"})])
        return _Msg(calls=[_Call("wait", {"reason": "nothing suspicious"})])
