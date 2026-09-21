#!/bin/bash
# start-server.sh --proto udp|tcp [--port 11198] [--subnet 10.88.0.0] [--dev ovpn-perf]
#
# A DCO server on the Linux machine, for measuring the Windows client against. The
# in-tree ovpn module carries the data channel, so the Linux side is not the limit; with
# userspace crypto it would be, and the number would say more about Linux than about the
# driver under test.
set -u

PROTO=udp; PORT=11198; SUBNET=10.88.0.0; DEV=ovpn-perf
KEYS=${KEYS:-/usr/share/doc/openvpn/examples/sample-keys}
RUN=${RUN:-$HOME/perf}

while [ $# -gt 0 ]; do
    case "$1" in
        --proto)  PROTO=$2; shift 2 ;;
        --port)   PORT=$2; shift 2 ;;
        --subnet) SUBNET=$2; shift 2 ;;
        --dev)    DEV=$2; shift 2 ;;
        --stop)   sudo pkill -f "$RUN/server.conf" 2>/dev/null; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

case "$PROTO" in
    udp|tcp) ;;
    *) echo "--proto must be udp or tcp" >&2; exit 2 ;;
esac

mkdir -p "$RUN"
sudo pkill -f "$RUN/server.conf" 2>/dev/null
sleep 1

# No log directive: output stays on stdout so a failure to start is visible. The caller
# redirects it once the server is known to come up.
cat > "$RUN/server.conf" <<EOF
dev $DEV
dev-type tun
proto $PROTO
port $PORT
mode server
tls-server
topology subnet
server $SUBNET 255.255.255.0
ca $KEYS/ca.crt
cert $KEYS/server.crt
key $KEYS/server.key
dh none
data-ciphers AES-256-GCM
keepalive 10 60
verb 3
EOF

sudo openvpn --config "$RUN/server.conf" > "$RUN/server.log" 2>&1 &
disown %% 2>/dev/null || true

for _ in $(seq 1 30); do
    ip -br addr show "$DEV" >/dev/null 2>&1 && break
    sleep 1
done

if ! ip -br addr show "$DEV" >/dev/null 2>&1; then
    echo "server did not come up:" >&2
    tail -20 "$RUN/server.log" >&2
    exit 1
fi

# Offload is the whole point, so say whether it actually happened rather than assuming.
if grep -qa "ovpn-dco device" "$RUN/server.log"; then
    echo "server up on $PROTO/$PORT, $(ip -br addr show "$DEV" | awk '{print $3}'), data channel offloaded"
else
    echo "server up on $PROTO/$PORT but WITHOUT offload: the numbers will be about Linux" >&2
    exit 1
fi
