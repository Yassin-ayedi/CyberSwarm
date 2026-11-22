"""Quick live checks of each LiveLab piece (run with the lab up): python -m arena.smoke_live"""
import json
import time

from .lab import LiveLab
from .scenario import make


def main():
    lab = LiveLab()
    lab.check()
    s = make(4242)
    print("scenario:", json.dumps(s.to_dict()))
    t0 = time.time()
    lab.prepare(s)
    print(f"[1] prepare ok in {time.time() - t0:.0f}s; solved at start = {len(lab.solved())}")
    r = lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/rest/products/search?q=' UNION SELECT 1--"})
    print("[2] red request reached:", r["reached"], "|", r["summary"].splitlines()[0] if r["summary"] else "")
    time.sleep(4)
    ev, dig = lab.observe()
    srcs = {e.get("src_ip") for e in ev if e.get("src_ip", "").startswith("10.10.1.")}
    print(f"[3] sensor events={len(ev)} client sources={sorted(srcs)}")
    print("    attacker ip seen:", s.attacker_ip in srcs, "| legit ip seen:", s.legit_ip in srcs)
    print("    digest:\n" + "\n".join("      " + l for l in dig.splitlines()))
    print("[4] block:", lab.blue_tool("block_ip", {"ip": s.attacker_ip}))
    r = lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/"})
    print("    red after block reached:", r["reached"])
    print("    unblock:", lab.blue_tool("unblock_ip", {"ip": s.attacker_ip}))
    r = lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/"})
    print("    red after unblock reached:", r["reached"])
    print("[5] rate limit:", lab.blue_tool("rate_limit", {"ip": s.attacker_ip, "per_second": 2}))
    print("    ids rule:", lab.blue_tool("add_ids_rule", {"name": "test", "content": "smoketest-xyz"}))
    lab.red_tool("http_request", {"method": "GET", "url": "http://10.10.2.11:3000/smoketest-xyz"})
    time.sleep(5)
    ev, dig = lab.observe()
    print("    blue rule fired:", any("BLUE test" in str(e.get("alert", {}).get("signature")) for e in ev))
    print("[6] legit ok/fail:", lab.legit_stats())
    r = lab.red_tool("http_request", {"method": "POST", "url": "http://10.10.2.11:3000/rest/user/login",
                                      "body": json.dumps({"email": "' OR 1=1--", "password": "x"})})
    print("[7] sqli login status:", r["summary"].splitlines()[0] if r["summary"] else "", "| solved now:", lab.solved())


if __name__ == "__main__":
    main()
