# Red's attacker box — Kali Linux. Lives only on attacker_net, no internet egress.
# Kali's repos reliably carry the pentest toolset; Debian-slim's pinned snapshot does not.
# Holds standard recon/testing utilities scoped to the lab. NO denial-of-service tooling.
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        sqlmap \
        gobuster \
        nikto \
        dirb \
        jq \
        python3 \
        python3-requests \
    && rm -rf /var/lib/apt/lists/*

# small wordlist for content discovery (gobuster/dirb)
ENV WORDLIST=/usr/share/dirb/wordlists/common.txt

# Red calls these via `docker exec` from the orchestrator's typed tool wrappers and the
# run_command tool; the guard applies budgets/output caps and the network enforces scope.
CMD ["sleep", "infinity"]
