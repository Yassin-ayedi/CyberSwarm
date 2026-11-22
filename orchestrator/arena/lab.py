"""
LiveLab: the real Docker lab as an arena backend.

Responsibilities:
  - prepare(scenario): clean slate for an episode (base firewall, base IDS rules, fresh
    Juice Shop scoreboard) and give the attacker / legit user the scenario's random IPs.
  - red_tool / blue_tool: execute the agents' tools (schemas in arena/tools.py).
  - ground truth for scoring: Juice Shop solves, legit-user success, firewall state.

Everything runs through `docker exec`; the host never talks to the lab networks directly.
"""
import datetime
import ipaddress
import json
import os
import re
import subprocess
import time
from urllib.parse import quote

from .sensors import Sensors, digest, inspect

LAB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "lab")
COMPOSE = os.path.join(LAB_DIR, "docker-compose.yml")
REDBOX, GATEWAY, TRAFFIC = "cs_redbox", "cs_gateway", "cs_traffic"
PRIMARY = {REDBOX: "10.10.1.50", TRAFFIC: "10.10.1.20"}
CLIENT_NET = ipaddress.ip_network("10.10.1.0/24")
LAB_NET = ipaddress.ip_network("10.10.0.0/16")
FLAG_RE = re.compile(r"CS\{[^}]+\}")
SAFE_CONTENT = re.compile(r"^[A-Za-z0-9 _./%=:?&@+\-*'()<>!,]{2,60}$")
BANNED_CMD = ["rm -rf /", "mkfs", "dd if=", ":(){", "shutdown", "reboot", "of=/dev/", "hping", "slowloris"]
ANSWER_RE = re.compile(r"\d+/tcp\s+open\b|HTTP/[12](?:\.[01])? \d{3}|\(Status: \d{3}\)|Status: \d{3}|"
                       r"\b[1-5]\d\d\b(?: [1-5]\d\d\b)+|available databases|is vulnerable|Parameter: |"
                       r"back-end DBMS")   # not "Host is up": with -Pn nmap says it even when blocked
TIMEOUT_MARKERS = ["timed out", "Connection refused", "couldn't connect", "Failed to connect",
                   "Operation timed out", "host seems down", "0 hosts up", "Resolving timed out"]


def _run(args, timeout=90):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return "[command timed out]"


def dexec(container, args, timeout=90):
    return _run(["docker", "exec", container] + args, timeout)


def _in(net, ip):
    """In the lab range, excluding x.x.x.1: on each Docker network that address is the
    Docker host's own bridge interface, not a lab machine."""
    try:
        a = ipaddress.ip_address(ip.split(":")[0].strip())
        return a in net and not str(a).endswith(".1")
    except ValueError:
        return False


def _scan_target(t):
    """A single lab IP, or a lab range no bigger than a /24. Returns (target, error)."""
    t = t.split(":")[0].strip()
    try:
        if "/" in t:
            n = ipaddress.ip_network(t, strict=False)
            if not n.subnet_of(LAB_NET):
                return None, "refused by the lab rules: range outside 10.10.0.0/16"
            if n.prefixlen < 24:
                return None, "refused by the lab rules: scan at most a /24 range at a time"
            return str(n), None
        a = ipaddress.ip_address(t)
    except ValueError:
        return None, f"refused: '{t}' is not an IP address or range"
    if a not in LAB_NET:
        return None, "refused by the lab rules: target outside 10.10.0.0/16"
    if str(a).endswith(".1"):
        return None, "refused by the lab rules: x.x.x.1 is the Docker host, outside the exercise"
    return str(a), None


# the Docker hosts' bridge addresses are never part of the exercise
NMAP_EXCLUDE = "10.10.1.1,10.10.2.1,10.10.3.1"


class LiveLab:
    name = "live"

    def __init__(self):
        self.eve = os.path.join(LAB_DIR, "logs", "eve.json")
        self.sensors = Sensors(self.eve)
        self.rule_sid = 2000000
        self.fw = {}             # ip -> "block" | "rate:N"   (Blue's current firewall decisions)
        self.blue_rules = []     # IDS rules Blue added this episode
        self.waf = []            # patterns Blue's WAF blocks this episode
        self._legit_since = None

    # ------------------------------------------------------------------ episode lifecycle
    def check(self):
        names = _run(["docker", "ps", "--format", "{{.Names}}"])
        missing = [c for c in (REDBOX, GATEWAY, TRAFFIC, "cs_juiceshop") if c not in names]
        if missing:
            raise RuntimeError(f"lab containers not running: {missing}. Start the lab first "
                               f"(docker compose up -d, THEN lab/setup.ps1).")
        # Docker Desktop re-enables bridge filtering when it (re)creates the lab networks;
        # with it on, nothing crosses the gateway. Must be 0 (lab/setup.ps1 sets it).
        nf = _run(["docker", "run", "--rm", "--privileged", "--network", "host", "alpine",
                   "sysctl", "-n", "net.bridge.bridge-nf-call-iptables"], 60).strip()
        if nf.endswith("1"):
            raise RuntimeError("Docker bridge filtering is ON, so traffic cannot cross the gateway. "
                               "Run lab/setup.ps1 now (after docker compose up), then retry.")

    def prepare(self, scn):
        self.fw, self.blue_rules, self.waf = {}, [], []
        # 1. base firewall (drops Blue's rules and the WAF redirect from the last episode)
        dexec(GATEWAY, ["nft", "-f", "/etc/nftables.conf"])
        dexec(GATEWAY, ["sh", "-c", "mkdir -p /etc/waf && : > /etc/waf/patterns.txt"])
        # 1b. fresh Flask app + database (anonymous volume renewed) and a clean attacker box,
        #     so nothing an agent changed in one episode survives into the next
        _run(["docker", "compose", "-f", COMPOSE, "up", "-d", "--force-recreate", "--renew-anon-volumes",
              "--no-deps", "db", "webapp"], timeout=180)
        dexec(REDBOX, ["sh", "-c", "rm -rf /root/.local/share/sqlmap /root/.sqlmap /tmp/* 2>/dev/null; true"])
        # 2. base IDS rules (drops rules Blue added last episode) + hot reload
        dexec(GATEWAY, ["sh", "-c",
                        "[ -f /etc/suricata/rules/local.rules.base ] || cp /etc/suricata/rules/local.rules "
                        "/etc/suricata/rules/local.rules.base; cp /etc/suricata/rules/local.rules.base "
                        "/etc/suricata/rules/local.rules; kill -USR2 $(pidof suricata) 2>/dev/null; true"])
        # 3. fresh Juice Shop (its scoreboard is in-memory)
        _run(["docker", "compose", "-f", COMPOSE, "restart", "juiceshop"], timeout=120)
        for _ in range(60):
            code = dexec(GATEWAY, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "3",
                                   "http://10.10.2.11:3000/rest/admin/application-version"], 10)
            if code.strip().endswith("200"):
                break
            time.sleep(2)
        # 4. scenario IPs: attacker and legit user get random addresses on the client network
        self._set_src_ip(REDBOX, scn.attacker_ip)
        self._set_src_ip(TRAFFIC, scn.legit_ip)
        time.sleep(3)
        self.sensors.mark_now()
        self._legit_since = self._now()

    def _set_src_ip(self, container, ip):
        prim = PRIMARY[container]
        script = (
            "IF=$(ip -o -4 addr show | awk '/10\\.10\\.1\\./{print $2; exit}'); "
            f"for a in $(ip -o -4 addr show dev $IF | awk '{{print $4}}'); do "
            f"  [ \"$a\" = \"{prim}/24\" ] || ip addr del $a dev $IF; done; "
            f"ip addr add {ip}/24 dev $IF 2>/dev/null; "
            f"ip route replace default via 10.10.1.254 src {ip}"
        )
        out = dexec(container, ["sh", "-c", script])
        if "RTNETLINK" in out and "File exists" not in out:
            print(f"[lab] warning setting {container} ip: {out.strip()}", flush=True)

    def set_attacker_ip(self, ip):
        """change_ip: move the attacker box to a new source address mid-episode."""
        self._set_src_ip(REDBOX, ip)

    @staticmethod
    def _now():
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # ------------------------------------------------------------------ observation
    def observe(self):
        ev = self.sensors.new_events()
        return ev, digest(ev)

    def legit_stats(self):
        """Legit user's successes/failures since the previous call (ground truth, not shown to Blue)."""
        since, self._legit_since = self._legit_since, self._now()
        logs = _run(["docker", "logs", "--since", since, TRAFFIC], timeout=20)
        return logs.count("legit cycle ok"), logs.count("request failed")

    def solved(self):
        out = dexec(GATEWAY, ["curl", "-s", "-m", "10", "http://10.10.2.11:3000/api/Challenges/"], 20)
        try:
            data = json.loads(out).get("data", [])
            return sorted(c.get("key") or c.get("name") for c in data if c.get("solved"))
        except Exception:
            return []

    def firewall_state(self):
        return dict(self.fw)

    def waf_state(self):
        return list(self.waf)

    # ------------------------------------------------------------------ Red tools
    def red_tool(self, name, args):
        """-> {"summary", "reached", "outcome"}.
        outcome: answered | waf (403 from the WAF) | refused (lab rules) | no_answer
        ("no_answer" is refined into "blocked" by the match engine when the defender had the
        attacker's address blocked; otherwise nothing was there or the command failed)."""
        r = self._red_tool(name, args)
        if r.get("outcome") is None:
            if "Blocked by the WAF" in r["summary"]:
                r["outcome"] = "waf"
            else:
                r["outcome"] = "answered" if r["reached"] else "no_answer"
        return r

    def _red_tool(self, name, args):
        try:
            if name == "scan_ports":
                t, err = _scan_target(str(args.get("target", "")))
                if err:
                    return {"summary": err, "reached": False, "outcome": "refused"}
                # a single host is scanned even if it ignores pings (-Pn); a range first finds
                # the live hosts (ping sweep) so it finishes in seconds instead of minutes
                pn = [] if "/" in t else ["-Pn"]
                out = dexec(REDBOX, ["nmap"] + pn + ["-T4", "--top-ports", "1000", "--host-timeout", "45s",
                                                     "--exclude", NMAP_EXCLUDE, t], 75)
                return {"summary": out[:2500], "reached": "/tcp" in out and "open" in out}
            if name == "http_request":
                url = quote(str(args.get("url", "")).strip(), safe=":/?&=%#@+!$'()*,;[]~-._")
                host = url.split("//", 1)[-1].split("/", 1)[0]
                if not _in(LAB_NET, host):
                    return {"summary": "refused by the lab rules: URL outside the exercise (10.10.0.0/16, not x.x.x.1)",
                            "reached": False, "outcome": "refused"}
                cmd = ["curl", "-s", "-i", "-m", "8", "-X", str(args.get("method", "GET")).upper(), url]
                hdrs = dict(args.get("headers") or {})
                body = args.get("body")
                if body is not None and not any(k.lower() == "content-type" for k in hdrs):
                    hdrs["Content-Type"] = "application/json"
                for k, v in hdrs.items():
                    cmd += ["-H", f"{k}: {v}"]
                if body is not None:
                    cmd += ["--data-raw", body if isinstance(body, str) else json.dumps(body)]
                out = dexec(REDBOX, cmd, 20)
                if not out.strip():
                    out = "(no response: the request failed or timed out)"
                return {"summary": out[:2500], "reached": out.startswith("HTTP/")}
            if name == "run_command":
                c = str(args.get("command", ""))
                if any(b in c.lower() for b in BANNED_CMD):
                    return {"summary": "refused: destructive or DoS command", "reached": False}
                out = dexec(REDBOX, ["timeout", "60", "sh", "-c", c], 75)
                # "answered" only on real evidence that a target replied: an open port, an HTTP
                # status line, a gobuster hit, or sqlmap finding something. Printing text is not enough
                # (nmap prints a report even when every packet was dropped).
                reached = bool(ANSWER_RE.search(out))
                return {"summary": (out or "(no output)")[:2500], "reached": reached}
            return {"summary": f"unknown tool {name}", "reached": False}
        except Exception as e:
            return {"summary": f"error: {e}", "reached": False}

    def red_raw(self, command, timeout=60):
        """Used by the scripted attackers."""
        return dexec(REDBOX, ["timeout", str(timeout), "sh", "-c", command], timeout + 15)

    # ------------------------------------------------------------------ Blue tools
    def blue_tool(self, name, args):
        ip = str(args.get("ip", "")).strip()
        if name in ("block_ip", "rate_limit", "unblock_ip", "inspect_ip", "raise_alert"):
            if not _in(CLIENT_NET, ip) or ip.endswith(".254"):
                return f"rejected: {ip!r} is not a client address (10.10.1.1-253)"
        if name == "inspect_ip":
            return inspect(self.sensors.history, ip)
        if name == "raise_alert":
            return f"incident recorded: {ip} ({args.get('attack_type', '?')})"
        # IP rules go in BOTH chains: forwarded traffic, and traffic diverted to the WAF proxy
        # (which terminates on the gateway itself, so it passes "input", not "forward")
        if name == "block_ip":
            self._fw_clear(ip)
            for chain in ("forward", "input"):
                dexec(GATEWAY, ["nft", "insert", "rule", "ip", "filter", chain, "ip", "saddr", ip,
                                "counter", "drop", "comment", f"\"blue {ip}\""])
            self.fw[ip] = "block"
            return f"all traffic from {ip} is now dropped at the gateway"
        if name == "rate_limit":
            n = max(1, min(50, int(args.get("per_second", 5))))
            self._fw_clear(ip)
            for chain in ("forward", "input"):
                dexec(GATEWAY, ["nft", "insert", "rule", "ip", "filter", chain, "ip", "saddr", ip,
                                "ct", "state", "new", "limit", "rate", "over", f"{n}/second", "counter", "drop",
                                "comment", f"\"blue {ip}\""])
            self.fw[ip] = f"rate:{n}"
            return f"{ip} limited to {n} new connections per second"
        if name == "block_pattern":
            pat = str(args.get("pattern", "")).strip().lower()
            if not SAFE_CONTENT.match(pat):
                return "rejected: pattern must be 2-60 plain characters (no quotes, ; or backslash)"
            if pat in self.waf:
                return f"the WAF already blocks '{pat}'"
            if not self.waf:      # first pattern: divert client traffic for the shop through the WAF
                dexec(GATEWAY, ["nft", "add", "rule", "ip", "nat", "prerouting", "ip", "saddr", "10.10.1.0/24",
                                "ip", "daddr", "10.10.2.11", "tcp", "dport", "3000", "ct", "mark", "set", "0x1",
                                "redirect", "to", ":8080",
                                "comment", "\"blue waf\""])
            self.waf.append(pat)
            self._waf_write()
            return f"WAF now rejects (HTTP 403) every web request to the shop containing '{pat}'"
        if name == "unblock_pattern":
            pat = str(args.get("pattern", "")).strip().lower()
            if pat not in self.waf:
                return f"the WAF has no pattern '{pat}'. Active: {self.waf or 'none'}"
            self.waf.remove(pat)
            self._waf_write()
            return f"removed WAF pattern '{pat}'. Active: {self.waf or 'none'}"
        if name == "unblock_ip":
            had = self._fw_clear(ip)
            self.fw.pop(ip, None)
            return f"removed {had} rule(s) for {ip}"
        if name == "add_ids_rule":
            content = str(args.get("content", ""))
            rname = re.sub(r"[^A-Za-z0-9 _-]", "", str(args.get("name", "blue rule")))[:40]
            if not SAFE_CONTENT.match(content):
                return "rejected: content must be 2-60 plain characters (no quotes, ; or backslash)"
            self.rule_sid += 1
            rule = (f'alert http any any -> $HOME_NET any (msg:"BLUE {rname}"; flow:to_server; '
                    f'content:"{content}"; nocase; sid:{self.rule_sid}; rev:1;)')
            dexec(GATEWAY, ["sh", "-c", f"echo '{rule}' >> /etc/suricata/rules/local.rules && "
                                        "kill -USR2 $(pidof suricata)"])
            self.blue_rules.append({"name": rname, "content": content})
            return f"IDS rule added and loaded: alert on '{content}'"
        if name == "wait":
            return "ok, no action"
        return f"unknown tool {name}"

    def _waf_write(self):
        body = "\n".join(self.waf).replace("'", "")
        dexec(GATEWAY, ["sh", "-c", f"printf '%s\\n' '{body}' > /etc/waf/patterns.txt"])

    def _fw_clear(self, ip):
        """Delete Blue's nft rules for this ip in both chains (found by their comment handle)."""
        n = 0
        for chain in ("forward", "input"):
            out = dexec(GATEWAY, ["nft", "-a", "list", "chain", "ip", "filter", chain])
            for line in out.splitlines():
                if f'"blue {ip}"' in line and "# handle" in line:
                    h = line.rsplit("# handle", 1)[1].strip()
                    dexec(GATEWAY, ["nft", "delete", "rule", "ip", "filter", chain, "handle", h])
                    n += chain == "forward"
        return n
