# Gateway: router + firewall + IDS sensor for the whole lab.
# Ubuntu base: Debian bookworm's pinned snapshot ships no suricata candidate;
# Ubuntu 24.04 carries Suricata 7.x in its default repos.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables \
        suricata \
        iproute2 \
        iptables \
        tcpdump \
        iputils-ping \
        curl \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY nftables.conf /etc/nftables.conf
COPY waf.py /waf.py
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY local.rules /etc/suricata/rules/local.rules
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Make sure the rules dir and a stub suricata.rules exist even without the ET ruleset.
RUN mkdir -p /etc/suricata/rules && touch /etc/suricata/rules/suricata.rules

ENTRYPOINT ["/entrypoint.sh"]
