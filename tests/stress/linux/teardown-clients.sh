#!/bin/bash
# teardown-clients.sh [count]   remove the client namespaces and their veth pairs.
set -u
N=${1:-8}
for i in $(seq 1 "$N"); do
    sudo ip netns pids "c$i" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
    sudo ip netns del "c$i" 2>/dev/null || true
    sudo ip link del "vc$i" 2>/dev/null || true
done
echo "removed $N namespaces"
