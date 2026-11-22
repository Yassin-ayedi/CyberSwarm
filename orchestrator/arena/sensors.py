"""
Incremental reader of Suricata's eve.json. Each call to new_events() returns only what was
written since the previous call (file offset cursor), which is exactly "what the sensors saw
since the last tick". digest() turns events into the compact text Blue reads.

Blue gets BOTH signature alerts and behaviour (per-source request volume, status codes,
paths). Behaviour is what lets it notice attacks that no signature covers (e.g. a password
brute force produces no alert, only many 401s from one source).
"""
import datetime
import json
import os
from collections import Counter, defaultdict


class Sensors:
    def __init__(self, eve_path):
        self.eve_path = eve_path
        self.offset = 0
        self.history = []      # every event seen this episode (for inspect_ip)
        self.start = datetime.datetime.now(datetime.timezone.utc)

    def mark_now(self):
        self.offset = os.path.getsize(self.eve_path) if os.path.exists(self.eve_path) else 0
        self.history = []
        self.start = datetime.datetime.now(datetime.timezone.utc)

    def _current(self, e):
        """Suricata writes a flow record only when the connection times out, so records of the
        PREVIOUS episode's traffic can arrive during this one ("ghost" sources). Keep only
        events whose traffic started after this episode began."""
        ts = (e.get("flow") or {}).get("start") if e.get("event_type") == "flow" else e.get("timestamp")
        try:
            return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z") >= self.start
        except (TypeError, ValueError):
            return True

    def new_events(self):
        if not os.path.exists(self.eve_path):
            return []
        size = os.path.getsize(self.eve_path)
        if size < self.offset:      # file was truncated/rotated
            self.offset = 0
        out = []
        with open(self.eve_path, "rb") as f:
            f.seek(self.offset)
            data = f.read()
        # only consume complete lines; a half-written last line is read next time
        cut = data.rfind(b"\n") + 1
        self.offset += cut
        for line in data[:cut].splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if self._current(e):
                out.append(e)
        self.history.extend(out)
        return out


def compact(events):
    """events -> structured summary (used for the dashboard and for the text digest)."""
    alerts = Counter()
    per_src = defaultdict(lambda: {"requests": 0, "status": Counter(), "paths": Counter(),
                                   "flows": 0, "ports": set(), "alerts": 0})
    for e in events:
        src = e.get("src_ip")
        if not src or not src.startswith("10.10.1."):
            continue          # only client-side sources are interesting to Blue
        s = per_src[src]
        et = e.get("event_type")
        if et == "alert":
            alerts[(src, e.get("alert", {}).get("signature", "?"))] += 1
            s["alerts"] += 1
        elif et == "http":
            h = e.get("http", {})
            s["requests"] += 1
            s["status"][h.get("status", "-")] += 1
            s["paths"][(h.get("http_method", "?") + " " + str(h.get("url", "?")))[:70]] += 1
        elif et == "flow":
            s["flows"] += 1
            if e.get("dest_port"):
                s["ports"].add(e["dest_port"])
    return alerts, per_src


def digest(events):
    alerts, per_src = compact(events)
    if not per_src:
        return "No traffic observed from the client network."
    lines = []
    if alerts:
        lines.append("IDS alerts:")
        for (src, sig), n in alerts.most_common(8):
            lines.append(f"  {src}  x{n}  {sig}")
    else:
        lines.append("IDS alerts: none")
    lines.append("Activity per source:")
    for src, s in sorted(per_src.items(), key=lambda kv: -(kv[1]["requests"] + kv[1]["flows"])):
        st = ", ".join(f"{k}:{v}" for k, v in s["status"].most_common(4)) or "-"
        top = "; ".join(p for p, _ in s["paths"].most_common(3)) or "-"
        lines.append(f"  {src}: {s['requests']} http requests (status {st}), {s['flows']} flows, "
                     f"{len(s['ports'])} distinct dest ports; top paths: {top}")
    return "\n".join(lines)


def inspect(history, ip, limit=12):
    reqs, alerts = [], []
    for e in history:
        if e.get("src_ip") != ip:
            continue
        if e.get("event_type") == "http":
            h = e.get("http", {})
            reqs.append(f"{h.get('http_method','?')} {str(h.get('url','?'))[:80]} -> {h.get('status','-')}"
                        f"  ua={str(h.get('http_user_agent','-'))[:30]}")
        elif e.get("event_type") == "alert":
            alerts.append(e.get("alert", {}).get("signature", "?"))
    if not reqs and not alerts:
        return f"No recorded activity from {ip} this episode."
    out = [f"Last HTTP requests from {ip} ({len(reqs)} total this episode):"] + ["  " + r for r in reqs[-limit:]]
    out.append(f"IDS alerts from {ip}: " + (", ".join(f"{s} x{n}" for s, n in Counter(alerts).most_common(6)) or "none"))
    return "\n".join(out)
