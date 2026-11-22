"""Live checks for the mvp2 fixes (run with the lab up): python -m arena.smoke_fixes"""
import time

from .lab import LiveLab, dexec, REDBOX
from .scenario import make


def line(r):
    return f"outcome={r['outcome']:<9} | " + " ".join(r["summary"].split())[:110]


def main():
    lab = LiveLab()
    lab.check()
    s = make(4243)
    t0 = time.time()
    lab.prepare(s)
    print(f"[1] prepare (incl. Flask+DB recreate, red-box clean) in {time.time() - t0:.0f}s")
    print("    flask reachable:", dexec(REDBOX, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "6",
                                                  "http://10.10.2.10:5000/"]).strip())
    r = lab.red_tool("scan_ports", {"target": "10.10.2.0/24"})
    print("[2] range scan  ", line(r))
    print("    hosts found:", [l.split()[-1] for l in r["summary"].splitlines() if l.startswith("Nmap scan report")],
          "| 3000 open:", "3000/tcp open" in r["summary"], "| 5000 open:", "5000/tcp open" in r["summary"])
    print("[3] .1 target   ", line(lab.red_tool("scan_ports", {"target": "10.10.2.1"})))
    print("    /16 range   ", line(lab.red_tool("scan_ports", {"target": "10.10.0.0/16"})))
    print("    no host     ", line(lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.5/"})))
    print("[4] waf:", lab.blue_tool("block_pattern", {"pattern": "union"}))
    print("    sqli w/ UNION", line(lab.red_tool("http_request", {"method": "GET",
          "url": "http://10.10.2.11:3000/rest/products/search?q=x')) UNION SELECT 1--"})))
    print("    normal req  ", line(lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/api/Products"})))
    time.sleep(3)
    ok, fail = lab.legit_stats()
    print(f"    customer through the WAF: ok={ok} fail={fail}")
    print("[5] block_ip:", lab.blue_tool("block_ip", {"ip": s.attacker_ip}))
    print("    after block ", line(lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/"})))
    print("    unblock:", lab.blue_tool("unblock_ip", {"ip": s.attacker_ip}), "| waf off:",
          lab.blue_tool("unblock_pattern", {"pattern": "union"}))
    print("    after unblock", line(lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/"})))


if __name__ == "__main__":
    main()
