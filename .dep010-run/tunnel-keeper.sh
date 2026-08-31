#!/usr/bin/env bash
# Keeps the .140 DB/redis/mocks tunnel up; reconnects if it drops.
WORKER=edierks@192.168.1.140
while true; do
  ssh -N \
    -o BatchMode=yes -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o TCPKeepAlive=yes -o ConnectTimeout=15 \
    -L 127.0.0.1:5432:127.0.0.1:5434 \
    -L 127.0.0.1:6379:127.0.0.1:6379 \
    -L 127.0.0.1:1025:127.0.0.1:1025 \
    -L 127.0.0.1:8025:127.0.0.1:8025 \
    -L 127.0.0.1:8443:127.0.0.1:8443 \
    -L 127.0.0.1:8181:127.0.0.1:8181 \
    -L 127.0.0.1:8282:127.0.0.1:8282 \
    "$WORKER"
  echo "$(date -u +%H:%M:%S) tunnel dropped; reconnecting in 3s" >&2
  sleep 3
done
