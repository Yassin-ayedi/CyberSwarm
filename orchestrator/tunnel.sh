#!/bin/bash
# Keep the SSH tunnel to the GPU VM's Ollama open; reconnect automatically if it drops.
# usage: bash tunnel.sh <key_file> <user@host>
KEY="$1"; DEST="$2"
while true; do
  ssh -i "$KEY" -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      -o ExitOnForwardFailure=yes -N -L 11434:localhost:11434 "$DEST"
  echo "[tunnel] dropped at $(date +%H:%M:%S), reconnecting in 3s" >&2
  sleep 3
done
