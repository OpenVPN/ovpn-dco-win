#!/bin/bash
# start-client.sh --server <ip> [--port 11198] [--dev ovpn-perf]
#
# A DCO client on the Linux machine, for measuring a Windows server against. The in-tree
# ovpn module carries the data channel, so this end is not the limit; with userspace
# crypto it would be, and the number would say more about Linux than about the driver
# under test.
set -u

SERVER=""; PORT=11198; DEV=ovpn-perf
KEYS=${KEYS:-/usr/share/doc/openvpn/examples/sample-keys}
RUN=${RUN:-$HOME/perf}

while [ $# -gt 0 ]; do
    case "$1" in
        --server) SERVER=$2; shift 2 ;;
        --port)   PORT=$2; shift 2 ;;
        --dev)    DEV=$2; shift 2 ;;
        --stop)   sudo pkill -f "$RUN/client.conf" 2>/dev/null; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -z "$SERVER" ] && { echo "--server is required" >&2; exit 2; }

mkdir -p "$RUN"
sudo pkill -f "$RUN/client.conf" 2>/dev/null
sleep 1

cat > "$RUN/client.conf" <<EOF
client
dev $DEV
dev-type tun
proto udp
remote $SERVER $PORT
nobind
ca $KEYS/ca.crt
cert $KEYS/client.crt
key $KEYS/client.key
remote-cert-tls server
data-ciphers AES-256-GCM
verb 3
EOF

sudo openvpn --config "$RUN/client.conf" > "$RUN/client.log" 2>&1 &
disown %% 2>/dev/null || true

for _ in $(seq 1 60); do
    ip -br addr show "$DEV" 2>/dev/null | grep -q '10\.' && break
    sleep 1
done

addr=$(ip -br addr show "$DEV" 2>/dev/null | awk '{print $3}')
if [ -z "$addr" ]; then
    echo "client did not come up:" >&2
    tail -20 "$RUN/client.log" >&2
    exit 1
fi

# Offload is the whole point, so say whether it actually happened rather than assuming.
if grep -qa "ovpn-dco device" "$RUN/client.log"; then
    echo "client up on udp/$PORT to $SERVER, $addr, data channel offloaded"
else
    echo "client up on udp/$PORT but WITHOUT offload: the numbers will be about Linux" >&2
    exit 1
fi
