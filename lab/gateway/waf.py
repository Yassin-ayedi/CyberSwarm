"""
Tiny web application firewall (WAF) on the gateway, used by Blue's block_pattern tool.

When Blue adds its first pattern, the lab redirects client traffic for Juice Shop
(10.10.2.11:3000) to this proxy (nft "redirect to :8080"). Every chunk the client sends is
URL-decoded, lower-cased and checked against /etc/waf/patterns.txt; on a match the client
gets "403 Blocked by the WAF" and the connection is closed. Otherwise bytes are piped to
Juice Shop unchanged. Blocks are logged to /var/log/suricata/waf.log (JSON lines).
"""
import asyncio
import json
import os
import time
import urllib.parse

PATTERNS = "/etc/waf/patterns.txt"
LOG = "/var/log/suricata/waf.log"
UPSTREAM = ("10.10.2.11", 3000)
DENY = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 19\r\n"
        b"Connection: close\r\n\r\nBlocked by the WAF\n")
_cache = {"mtime": None, "pats": []}


def patterns():
    try:
        m = os.path.getmtime(PATTERNS)
    except OSError:
        return []
    if m != _cache["mtime"]:
        with open(PATTERNS, encoding="utf-8", errors="ignore") as f:
            _cache["pats"] = [l.strip().lower() for l in f if l.strip()]
        _cache["mtime"] = m
    return _cache["pats"]


def log(src, pat, sample):
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps({"ts": time.time(), "src_ip": src, "pattern": pat, "sample": sample[:160]}) + "\n")
    except OSError:
        pass


async def handle(cr, cw):
    src = (cw.get_extra_info("peername") or ["?"])[0]
    try:
        ur, uw = await asyncio.open_connection(*UPSTREAM)
    except OSError:
        cw.close()
        return

    async def client_to_server():
        try:
            while True:
                d = await cr.read(65536)
                if not d:
                    break
                txt = urllib.parse.unquote_plus(d.decode("latin-1")).lower()
                for p in patterns():
                    if p in txt:
                        cw.write(DENY)
                        await cw.drain()
                        log(src, p, txt.split("\r\n", 1)[0])
                        cw.close()
                        uw.close()
                        return
                uw.write(d)
                await uw.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            uw.close()

    async def server_to_client():
        try:
            while True:
                d = await ur.read(65536)
                if not d:
                    break
                cw.write(d)
                await cw.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            cw.close()

    await asyncio.gather(client_to_server(), server_to_client(), return_exceptions=True)


async def main():
    os.makedirs(os.path.dirname(PATTERNS), exist_ok=True)
    open(PATTERNS, "a").close()
    srv = await asyncio.start_server(handle, "0.0.0.0", 8080)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
