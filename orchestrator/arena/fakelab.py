"""
FakeLab: an in-memory simulation of the lab with the same interface as LiveLab.

Purpose: test the whole arena (engine, scoring, logging, dashboard, learning loop) without
Docker or the GPU. It is NOT a realistic simulator; it just produces plausible sensor events:
the legit user browses every tick, Red's actions produce HTTP events and sometimes IDS alerts,
and Blue's firewall decisions really stop (or slow) the matching source.
"""
import random

from .sensors import digest, inspect

JS = "10.10.2.11"


class FakeLab:
    name = "fake"

    def __init__(self, seed=0):
        self.rng = random.Random(seed)
        self.fw = {}
        self.blue_rules = []
        self.history = []
        self.pending = []
        self.scn = None
        self.solved_set = set()
        self._legit = [0, 0]

    def check(self):
        return True

    def prepare(self, scn):
        self.scn, self.fw, self.blue_rules, self.waf = scn, {}, [], []
        self.atk = scn.attacker_ip
        self.history, self.pending, self.solved_set = [], [], set()
        self._legit = [0, 0]

    def _allowed(self, ip):
        rule = self.fw.get(ip)
        if rule == "block":
            return False
        if rule and rule.startswith("rate:"):
            return self.rng.random() < 0.3
        return True

    def _http(self, ip, method, url, status, alert=None):
        self.pending.append({"event_type": "flow", "src_ip": ip, "dest_ip": JS, "dest_port": 3000})
        self.pending.append({"event_type": "http", "src_ip": ip, "dest_ip": JS, "dest_port": 3000,
                             "http": {"http_method": method, "url": url, "status": status,
                                      "http_user_agent": "curl/8" if ip == self.atk else "Mozilla/5.0"}})
        hit = alert
        for r in self.blue_rules:
            if r["content"].lower() in url.lower():
                hit = "BLUE " + r["name"]
        if hit:
            self.pending.append({"event_type": "alert", "src_ip": ip, "dest_ip": JS, "alert": {"signature": hit}})

    def observe(self):
        # the legit user browses every tick
        ip = self.scn.legit_ip
        for _ in range(3):
            if self._allowed(ip):
                path = self.rng.choice(["/", "/api/Products", "/rest/products/search?q=apple"])
                self._http(ip, "GET", path, 200)
                self._legit[0] += 1
            else:
                self._legit[1] += 1
        ev, self.pending = self.pending, []
        self.history.extend(ev)
        return ev, digest(ev)

    def legit_stats(self):
        ok, fail = self._legit
        self._legit = [0, 0]
        return ok, fail

    def solved(self):
        return sorted(self.solved_set)

    def firewall_state(self):
        return dict(self.fw)

    def set_attacker_ip(self, ip):
        self.atk = ip

    def waf_state(self):
        return list(getattr(self, "waf", []))

    def red_tool(self, name, args):
        ip = self.atk
        if not self._allowed(ip):
            return {"summary": "(no response: the request timed out)", "reached": False}
        if name == "scan_ports":
            self.pending.append({"event_type": "alert", "src_ip": ip, "alert": {"signature": "CS port scan (many SYN)"}})
            for p in (22, 80, 3000, 5000, 8080):
                self.pending.append({"event_type": "flow", "src_ip": ip, "dest_port": p})
            return {"summary": "3000/tcp open\n5000/tcp open", "reached": True}
        url = str(args.get("url") or args.get("command") or "/")
        path = "/" + url.split("//", 1)[-1].split("/", 1)[-1] if "//" in url else url[:60]
        sqli = any(s in url.lower() for s in ("' or", "union", "1=1", "sqlmap"))
        body = str(args.get("body") or "")
        sqli = sqli or "' or" in body.lower()
        alert = "CS SQLi tautology OR" if sqli and self.rng.random() < 0.8 else None
        status = 200 if self.rng.random() < 0.6 else self.rng.choice([401, 404, 500])
        self._http(ip, str(args.get("method", "GET")), path, status, alert)
        if sqli and status == 200:
            self.solved_set.add("loginAdminChallenge")
        if "/metrics" in url:
            self.solved_set.add("exposedMetricsChallenge")
        return {"summary": f"HTTP/1.1 {status}\n(simulated response)", "reached": True}

    def red_raw(self, command, timeout=60):
        ip = self.atk
        if not self._allowed(ip):
            return "curl: (28) Connection timed out"
        n = self.rng.randint(4, 12)
        for _ in range(n):
            self._http(ip, "POST" if "login" in command else "GET",
                       "/rest/user/login" if "login" in command else f"/x{self.rng.randint(1, 999)}",
                       401 if "login" in command else 404,
                       "CS SQLi tautology OR" if "sqlmap" in command and self.rng.random() < 0.5 else None)
        return "401 " * n if "login" in command else "404 " * n

    def blue_tool(self, name, args):
        ip = str(args.get("ip", ""))
        if name == "inspect_ip":
            return inspect(self.history, ip)
        if name == "raise_alert":
            return f"incident recorded: {ip}"
        if name == "block_ip":
            self.fw[ip] = "block"
            return f"all traffic from {ip} is now dropped at the gateway"
        if name == "rate_limit":
            self.fw[ip] = f"rate:{args.get('per_second', 5)}"
            return f"{ip} rate limited"
        if name == "unblock_ip":
            self.fw.pop(ip, None)
            return f"removed rules for {ip}"
        if name == "block_pattern":
            self.waf = getattr(self, "waf", []) + [str(args.get("pattern", "")).lower()]
            return "WAF pattern added"
        if name == "unblock_pattern":
            self.waf = [p for p in getattr(self, "waf", []) if p != str(args.get("pattern", "")).lower()]
            return "WAF pattern removed"
        if name == "add_ids_rule":
            self.blue_rules.append({"name": str(args.get("name", "rule")), "content": str(args.get("content", "x"))})
            return "IDS rule added"
        return "ok, no action"
