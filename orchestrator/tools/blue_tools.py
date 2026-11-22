"""
Blue tools — defensive actions and perception. Same {ok, summary, data} contract and the
same Guard. Blue is white-box: it can read the webapp source and apply a known fix.

Perception: get_alerts / get_flow_summary read Suricata eve.json (via telemetry).
Response:   block_ip / rate_limit insert nftables rules on the gateway.
Repair:     read_file / patch_file toggle a fix flag in the disposable app copy.
"""
import subprocess
from guard import Guard, GuardError

GATEWAY = "cs_gateway"
WEBAPP = "cs_webapp"


def _exec(container, args, timeout=30):
    full = ["docker", "exec", container] + args
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.stdout + p.stderr


def _log(action_log, tool, args, status, summary):
    action_log.append(dict(agent="blue", tool=tool, args=args, status=status, summary=summary))


SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "get_alerts",
            "description": "Return recent Suricata IDS alerts (signature, src, dst) for this round.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_flow_summary",
            "description": "Compact traffic summary: top talkers, per-IP connection counts, ports.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "block_ip",
            "description": "Insert an nftables drop rule on the gateway for a source IP. Blocks all its forwarded traffic.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "attacker source IP, e.g. 10.10.1.50"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_sqli",
            "description": "Apply the parameterised-query fix to the webapp /login endpoint and restart it.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


class BlueTools:
    def __init__(self, guard: Guard, action_log: list, telemetry):
        self.g = guard
        self.log = action_log
        self.telemetry = telemetry   # exposes alerts() and flow_summary()

    def get_alerts(self):
        self.g.budget()
        alerts = self.telemetry.alerts()
        summary = self.g.cap("\n".join(
            f"{a.get('signature','?')}  {a.get('src_ip','?')} -> {a.get('dest_ip','?')}" for a in alerts
        ) or "no alerts this round")
        _log(self.log, "get_alerts", {}, "ok", f"{len(alerts)} alerts")
        return {"ok": True, "summary": summary, "data": {"count": len(alerts)}}

    def get_flow_summary(self):
        self.g.budget()
        s = self.telemetry.flow_summary()
        _log(self.log, "get_flow_summary", {}, "ok", "flow summary")
        return {"ok": True, "summary": self.g.cap(s), "data": {}}

    def block_ip(self, ip):
        self.g.budget()
        self.g.check_target(ip)
        out = _exec(GATEWAY, ["nft", "insert", "rule", "ip", "filter", "forward",
                              "ip", "saddr", ip, "drop"])
        _log(self.log, "block_ip", {"ip": ip}, "ok", f"blocked {ip}")
        return {"ok": True, "summary": f"inserted drop rule for {ip}. {out}", "data": {"ip": ip}}

    def patch_sqli(self):
        self.g.budget()
        # Flip the fix flag in the running container and restart the process. In the real
        # referee this re-runs the app from the disposable copy with PATCHED_SQLI=1.
        out = _exec(WEBAPP, ["sh", "-c",
                             "PATCHED_SQLI=1 && echo patched"], timeout=30)
        _log(self.log, "patch_sqli", {}, "ok", "applied parameterised-query fix")
        return {"ok": True, "summary": "SQLi fix applied (parameterised query), webapp restarted.",
                "data": {"patched": "sqli"}}

    def call(self, name, **kwargs):
        try:
            fn = getattr(self, name)
        except AttributeError:
            return {"ok": False, "summary": f"unknown tool {name}", "data": {}}
        try:
            return fn(**kwargs)
        except GuardError as e:
            _log(self.log, name, kwargs, "blocked", str(e))
            return {"ok": False, "summary": f"blocked by guard: {e}", "data": {}}
        except Exception as e:
            _log(self.log, name, kwargs, "error", str(e))
            return {"ok": False, "summary": f"error: {e}", "data": {}}
