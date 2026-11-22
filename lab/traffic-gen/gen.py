"""
Legitimate-user simulator for the Juice Shop target. Produces the "normal" traffic class
and the availability metric: if these requests start failing, the app is down (Blue
over-blocked, or Red broke it). Legit users browse — they do NOT inject.
"""
import os
import time
import random
import requests

TARGET = os.environ.get("TARGET", "http://10.10.2.11:3000")
SEARCHES = ["apple", "juice", "banana", "cookie", "", "lemon"]


def one_cycle():
    try:
        requests.get(f"{TARGET}/", timeout=5)
        requests.get(f"{TARGET}/api/Products", timeout=5)
        requests.get(f"{TARGET}/rest/products/search", params={"q": random.choice(SEARCHES)}, timeout=5)
        print("[traffic] legit cycle ok", flush=True)
    except Exception as e:
        print(f"[traffic] request failed: {e}", flush=True)


if __name__ == "__main__":
    print(f"[traffic] generating legit load against {TARGET}", flush=True)
    while True:
        one_cycle()
        time.sleep(random.uniform(1.5, 4.0))   # randomised so flows look human
