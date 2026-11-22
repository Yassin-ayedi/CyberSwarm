"""
guard.py — the safety boundary. EVERY tool call passes validate() BEFORE execution.
This is enforced in code, independent of what the LLM asks. Documented in the report's
safety section.

Checks:
  - target must be inside the lab subnets (10.10.0.0/16); anything else is rejected
  - per-round call budget and per-tool output cap
  - no shell metacharacters smuggled into args
"""
import ipaddress
import re

LAB_NET = ipaddress.ip_network("10.10.0.0/16")
MAX_CALLS_PER_ROUND = 40
MAX_OUTPUT_CHARS = 4000
# args are passed as a list to subprocess (never a shell string), but reject obvious shell
# injection attempts anyway as defence in depth.
_FORBIDDEN = re.compile(r"[;&|`$><\n]|\.\./\.\./\.\.")


class GuardError(Exception):
    pass


class Guard:
    def __init__(self, max_calls=MAX_CALLS_PER_ROUND):
        self.max_calls = max_calls
        self.calls_made = 0

    def reset(self):
        self.calls_made = 0

    def check_target(self, target: str):
        """target is an IP or host:port — the destination the tool will hit."""
        host = target.split(":")[0].strip()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise GuardError(f"target '{host}' is not an IP in the lab range")
        if ip not in LAB_NET:
            raise GuardError(f"target {ip} is outside the lab subnet {LAB_NET} - rejected")

    def check_arg(self, arg: str):
        if _FORBIDDEN.search(arg):
            raise GuardError(f"argument contains forbidden characters: {arg!r}")

    def budget(self):
        if self.calls_made >= self.max_calls:
            raise GuardError(f"round call budget ({self.max_calls}) exhausted")
        self.calls_made += 1

    def cap(self, text: str) -> str:
        if text is None:
            return ""
        return text[:MAX_OUTPUT_CHARS]


# simple self-test: `python -I guard.py`
if __name__ == "__main__":
    g = Guard()
    for t in ["10.10.2.10:5000", "8.8.8.8", "10.10.3.10"]:
        try:
            g.check_target(t)
            print(f"ALLOW {t}")
        except GuardError as e:
            print(f"BLOCK {t}: {e}")
