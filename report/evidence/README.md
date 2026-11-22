# Report evidence — CyberSwarm lab

Captured from a live run of the lab (attacker `10.10.1.50`, legit users `10.10.1.20`,
webapp `10.10.2.10`, db `10.10.3.10`, gateway `.254` on each segment).

| File | What it shows | Report section |
|---|---|---|
| `01_ping_across_gateway.txt` | Ping red-box → webapp, **TTL 63** = routed through the gateway (not a direct link) | Test screenshots (Ping) |
| `02_round_capture.pcap` | Full packet capture of a round on the gateway's `eth0`. Open in **Wireshark**; filter `http` to see the SQLi/traversal requests, or `tcp.flags.syn==1` for the port scan | Test screenshots (Wireshark) |
| `03_suricata_alerts.txt` | Suricata IDS alerts: SQLi UNION, path traversal, tautology `1=1`, port scan — all with the real attacker IP; plus HTTP parse counts (legit vs attacker) | ML/IDS perception, results |

## How to regenerate
```powershell
cd lab
./setup.ps1                 # bridge-nf fix (once per Docker Desktop restart)
docker compose up -d --build
# then re-run the evidence steps, or just take fresh screenshots of:
docker exec cs_redbox ping -c 4 10.10.2.10
docker exec cs_gateway tcpdump -i eth0 -w /var/log/suricata/capture.pcap   # -> lab/logs/capture.pcap
```

## Suggested screenshots for the report
1. **Ping**: the `01_ping_across_gateway.txt` output (highlight `ttl=63`).
2. **Wireshark**: open `02_round_capture.pcap`, show the HTTP stream of a SQLi request (Follow TCP Stream).
3. **IDS**: the `03_suricata_alerts.txt` table, next to a `docker compose ps` showing the topology.
