#!/bin/sh
# Gateway startup: enable forwarding, load the firewall, start the IDS, keep running.
set -e

echo "[gateway] enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[gateway] loading nftables ruleset"
nft -f /etc/nftables.conf

# No NAT: cross-segment routing works with source IPs intact (see docker VM bridge-nf
# note in README). Preserving the real source IP is what lets Blue detect and block the
# attacker by address. Return paths work because every container's default route is the
# gateway.

# Find the attacker-facing interface by IP, NOT by name: Docker does not guarantee eth
# ordering across container recreation, so a hardcoded eth0 can end up on the wrong segment
# (which silently zeroes all detections). Sniff whichever interface holds 10.10.1.254.
ATK_IF=$(ip -o -4 addr show | awk '/10\.10\.1\.254\//{print $2; exit}')
ATK_IF=${ATK_IF:-eth0}
echo "[gateway] starting Suricata on $ATK_IF (attacker_net side, IDS mode, libpcap)"
# All client traffic — legit users AND the attacker — enters the dmz through this interface,
# so Suricata sees complete bidirectional HTTP streams with real source IPs. -k none skips
# checksum validation (Docker/VM offload leaves "invalid" checksums that would otherwise drop
# packets from reassembly, so HTTP never parses and content rules never fire).
suricata -c /etc/suricata/suricata.yaml --pcap="$ATK_IF" -k none -v &

echo "[gateway] starting the WAF proxy on :8080 (only used once Blue adds a block_pattern)"
python3 /waf.py &

echo "[gateway] up. Blocking is Blue-controlled via nft from the orchestrator."
# Keep PID 1 alive; tcpdump here is handy for the Wireshark screenshot:
#   docker exec cs_gateway tcpdump -i any -w /var/log/suricata/capture.pcap
tail -f /dev/null
