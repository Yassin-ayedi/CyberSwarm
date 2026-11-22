# CyberSwarm lab setup — run ONCE per Docker Desktop session before `docker compose up`.
#
# Docker Desktop (WSL2) runs every bridged frame through the VM's firewall, which drops
# traffic between different Docker networks. Our gateway routes between three such networks,
# so that filtering must be turned off at the bridge level or nothing crosses the gateway.
# This is the single documented prerequisite for the lab's routing to work on Docker Desktop.
#
# It resets when Docker Desktop restarts, so re-run it after each restart. It only tells the
# Linux bridge to stop invoking iptables on bridged frames; it does not touch the host OS.

$ErrorActionPreference = "Stop"
$dockerBin = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin"
if (Test-Path $dockerBin) { $env:Path = "$dockerBin;" + $env:Path }

# Ensure a tiny local image exists for the privileged helper (no registry auth needed if local).
docker image inspect alpine:latest *> $null
if ($LASTEXITCODE -ne 0) { docker pull alpine:latest }

Write-Host "[setup] disabling bridge-nf-call-iptables in the Docker VM..."
docker run --rm --privileged --network host alpine sysctl -w net.bridge.bridge-nf-call-iptables=0
docker run --rm --privileged --network host alpine sysctl -w net.bridge.bridge-nf-call-ip6tables=0

Write-Host "[setup] done. Cross-segment routing through the gateway will now work."
Write-Host "[setup] next: docker compose up -d --build"
