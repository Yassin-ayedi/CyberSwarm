"""
CyberSwarm console server: serves the dashboard and lets it manage experiments.

    python dashboard/server.py            # then open http://localhost:8000/dashboard/

An "experiment" is one group of episodes: a training phase, then the held-out test with the
trained defender, then (optionally) the same test with an untrained defender as baseline.
The API runs one experiment at a time (there is only one lab):

  GET  /api/experiments          list experiments with their settings, notes and status
  POST /api/experiments          create + start one {name, train_episodes, test_episodes, ticks, baseline, notes}
  GET  /api/job                  the running job (state, step, last log lines)
  POST /api/job/stop             stop the running job (finished episodes are kept)

Listens on 127.0.0.1 only. Standard library only.
"""
import datetime
import http.server
import json
import os
import re
import subprocess
import sys
import threading
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ORCH = os.path.join(ROOT, "orchestrator")
RUNS = os.path.join(ROOT, "runs", "arena")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,30}$")
LOCK = threading.Lock()
JOB = {"state": "idle"}          # idle | running | done | stopped | failed
PROC = {"p": None}


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)


def _clear_live(name):
    p = os.path.join(RUNS, "index.json")
    idx = _read_json(p, {})
    for v in idx.get(name, {}).values():
        v["live"] = None
    _write_json(p, idx)


def experiments():
    idx = _read_json(os.path.join(RUNS, "index.json"), {})
    out = []
    for name, phases in idx.items():
        meta = _read_json(os.path.join(RUNS, name, "experiment.json"), {})
        if meta.get("hidden"):
            continue
        out.append({"name": name, "phases": phases, **meta,
                    "running": JOB.get("state") == "running" and JOB.get("name") == name})
    out.sort(key=lambda e: e.get("created", ""), reverse=True)
    return out


def model_reachable():
    try:
        with urllib.request.urlopen("http://localhost:11434/api/version", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def run_job(name, steps, log_path):
    for i, (label, args) in enumerate(steps):
        with LOCK:
            if JOB["state"] != "running":
                return
            JOB.update(step=i, step_label=label)
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"\n===== {label} =====\n")
            log.flush()
            env = dict(os.environ, PYTHONIOENCODING="utf-8")
            p = subprocess.Popen([sys.executable, "-u", "arena_main.py"] + args, cwd=ORCH,
                                 stdout=log, stderr=subprocess.STDOUT, env=env)
            PROC["p"] = p
            rc = p.wait()
        with LOCK:
            if JOB["state"] != "running":       # stopped by the user
                _clear_live(name)
                return
            if rc != 0:
                JOB.update(state="failed", ended=_now(), error=f"{label} exited with code {rc}")
                _clear_live(name)
                return
    with LOCK:
        JOB.update(state="done", ended=_now())


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def start(body):
    name = str(body.get("name", "")).strip().lower()
    if not NAME_RE.match(name):
        return 400, {"error": "Name: 2-31 characters, lowercase letters, digits, - or _"}
    if os.path.exists(os.path.join(RUNS, name)):
        return 400, {"error": f"An experiment called '{name}' already exists"}
    with LOCK:
        if JOB.get("state") == "running":
            return 409, {"error": f"Experiment '{JOB['name']}' is still running. Stop it first."}
    if not model_reachable():
        return 400, {"error": "The model server is not reachable on localhost:11434. Start the SSH tunnel to the GPU VM."}
    tr = max(1, min(50, int(body.get("train_episodes", 8))))
    te = max(1, min(50, int(body.get("test_episodes", 8))))
    ticks = max(6, min(30, int(body.get("ticks", 18))))
    baseline = bool(body.get("baseline", True))
    meta = {"created": _now(), "notes": str(body.get("notes", ""))[:400],
            "settings": {"train_episodes": tr, "test_episodes": te, "ticks": ticks, "baseline": baseline}}
    _write_json(os.path.join(RUNS, name, "experiment.json"), meta)
    steps = [("Training", ["train", "--run", name, "--episodes", str(tr), "--ticks", str(ticks)]),
             ("Held-out test · trained defender", ["eval", "--run", name, "--attackers", "scripted",
                                                   "--episodes", str(te), "--ticks", str(ticks)])]
    if baseline:
        steps.append(("Held-out test · untrained defender", ["eval", "--run", name, "--attackers", "scripted",
                                                             "--episodes", str(te), "--ticks", str(ticks), "--untrained"]))
    log_path = os.path.join(RUNS, name, "job.log")
    with LOCK:
        JOB.clear()
        JOB.update(state="running", name=name, started=_now(), steps=[s[0] for s in steps], step=0,
                   step_label=steps[0][0], settings=meta["settings"], log=os.path.relpath(log_path, ROOT))
    threading.Thread(target=run_job, args=(name, steps, log_path), daemon=True).start()
    return 200, {"ok": True, "name": name}


def stop():
    with LOCK:
        if JOB.get("state") != "running":
            return 400, {"error": "Nothing is running"}
        JOB.update(state="stopped", ended=_now())
        p = PROC.get("p")
    if p and p.poll() is None:
        p.terminate()
    return 200, {"ok": True}


def job_status():
    with LOCK:
        j = {k: v for k, v in JOB.items()}
    if j.get("log"):
        try:
            with open(os.path.join(ROOT, j["log"]), encoding="utf-8", errors="replace") as f:
                j["tail"] = f.read()[-3000:].splitlines()[-14:]
        except OSError:
            j["tail"] = []
    j["model_reachable"] = model_reachable() if j.get("state") != "running" else True
    return j


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/experiments"):
            return self._send(200, experiments())
        if self.path.startswith("/api/job"):
            return self._send(200, job_status())
        if self.path in ("/", ""):
            self.send_response(302)
            self.send_header("Location", "/dashboard/")
            self.end_headers()
            return
        return super().do_GET()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body = {}
        if self.path == "/api/experiments":
            return self._send(*start(body))
        if self.path == "/api/job/stop":
            return self._send(*stop())
        return self._send(404, {"error": "unknown endpoint"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"CyberSwarm console on http://localhost:{port}/dashboard/", flush=True)
    srv.serve_forever()
