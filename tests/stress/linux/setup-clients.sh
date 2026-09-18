#!/bin/bash
# setup-clients.sh [count]
#
# Create one network namespace per client, each wired to the uplink through a veth pair
# plus NAT.
#
# Every client is assigned an address from the same server pool, so they cannot share a
# routing table: the kernel could not tell which tun to use to reach a given peer. A
# namespace per client gives each its own table, which is what client-to-client needs.
#
# The veth MTU is matched to the uplink. A veth left at the default 1500 over a smaller
# uplink (WSL2 uses 1450) drops full-size encapsulated packets with no diagnostic,
# which resembles a driver bug: ping works while bulk TCP collapses.
set -e

N=${1:-8}
DUT=${DUT:-}
UPLINK=$(ip route show default | awk '{print $5; exit}')
UPLINK_MTU=$(ip -o link show "$UPLINK" | grep -o 'mtu [0-9]*' | cut -d' ' -f2)

sudo sysctl -qw net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -o "$UPLINK" -j MASQUERADE 2>/dev/null ||
    sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o "$UPLINK" -j MASQUERADE

for i in $(seq 1 "$N"); do
    ns=c$i
    sudo ip netns del "$ns" 2>/dev/null || true
    sudo ip link del "v$ns" 2>/dev/null || true

    sudo ip netns add "$ns"
    sudo ip link add "v$ns" type veth peer name "v${ns}n"
    sudo ip link set "v${ns}n" netns "$ns"

    sudo ip addr add "10.200.$i.1/30" dev "v$ns"
    sudo ip link set "v$ns" mtu "$UPLINK_MTU"
    sudo ip link set "v$ns" up

    sudo ip netns exec "$ns" ip addr add "10.200.$i.2/30" dev "v${ns}n"
    sudo ip netns exec "$ns" ip link set "v${ns}n" mtu "$UPLINK_MTU"
    sudo ip netns exec "$ns" ip link set "v${ns}n" up
    sudo ip netns exec "$ns" ip link set lo up
    sudo ip netns exec "$ns" ip route add default via "10.200.$i.1"
done

echo "created $N namespaces (uplink $UPLINK, mtu $UPLINK_MTU)"
echo "max client tun-mtu for this uplink: $((UPLINK_MTU - 60))"

if [ -n "$DUT" ]; then
    if sudo ip netns exec c1 ping -c1 -W2 "$DUT" >/dev/null 2>&1; then
        echo "c1 -> $DUT reachable"
    else
        echo "c1 -> $DUT UNREACHABLE (check routing and forwarding on the path)" >&2
        exit 1
    fi
fi
