#!/bin/bash
# swarm.sh --server <ip> [--pairs 4] [--swarm 16] [--flood 800] [--duration 900]
#          [--hold 1.5] [--outdir <dir>] [--keys <dir>] [--port 11197] [--tun-mtu 1390]
#
# Three workloads against the device under test at the same time:
#
#   pairs    pairs*2 clients stay connected and run iperf3 to each other. With
#            client-to-client the driver relays them, so this drives the peer-table
#            lookup in the TX path.
#   swarm    clients in independent loops: connect, ping-flood the server tunnel
#            address for --hold seconds, get killed mid-flight, reconnect. Every
#            teardown races in-flight data against peer free and timer detach, while
#            mutating the table the pairs are reading. One namespace and veth pair
#            each, so the count cannot go far.
#   flood    clients on dev null: no interface, address or routes. They handshake,
#            become a peer, stay idle for --flood-hold seconds and exit, a whole wave
#            at a time. No data path at all, one process each, which is how the peer
#            count gets high.
#
# Namespaces must already exist (see setup-clients.sh). Progress is printed while it
# runs; a JSON summary is the last line. Logs are kept under --outdir for triage.
set -u

SERVER=""; PORT=11197; PAIRS=4; SWARM=16; DURATION=900; HOLD=1.5
# must match the server's client-config-dir entry
IROUTE_PROBE=10.90.0.5
FLOOD=800; FLOOD_HOLD=5; FLOOD_GIVEUP=120
TUN_MTU=1390; OUTDIR=""
KEYS=${KEYS:-/usr/share/doc/openvpn/examples/sample-keys}
OVPN=${OVPN:-openvpn}

while [ $# -gt 0 ]; do
    case "$1" in
        --server)   SERVER=$2; shift 2 ;;
        --port)     PORT=$2; shift 2 ;;
        --pairs)    PAIRS=$2; shift 2 ;;
        --swarm)    SWARM=$2; shift 2 ;;
        --flood)    FLOOD=$2; shift 2 ;;
        --flood-hold) FLOOD_HOLD=$2; shift 2 ;;
        --flood-giveup) FLOOD_GIVEUP=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --hold)     HOLD=$2; shift 2 ;;
        --tun-mtu)  TUN_MTU=$2; shift 2 ;;
        --keys)     KEYS=$2; shift 2 ;;
        --outdir)   OUTDIR=$2; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[ -z "$SERVER" ] && { echo "--server <ip> is required" >&2; exit 2; }

[ -z "$OUTDIR" ] && OUTDIR="${TMPDIR:-/tmp}/ovpn-stress-$(date +%Y%m%d-%H%M%S)"
R=$OUTDIR/clients
mkdir -p "$R"
NT=$((PAIRS * 2))
SERVER_TUN=10.79.0.1
START=$(date +%s)
END=$((START + DURATION))

mkconf() {
    cat > "$R/$1.conf" <<EOF
client
dev tun
proto udp4
remote $SERVER $PORT
nobind
ca $KEYS/ca.crt
cert $KEYS/client.crt
key $KEYS/client.key
remote-cert-tls server
data-ciphers AES-128-GCM
tun-mtu $TUN_MTU
keepalive 10 60
verb 3
log-append $R/$1.log
# A client on kernel DCO does not advertise epoch data keys, so the server never
# negotiates them and no rotation happens. Keep the client data channel in userspace.
disable-dco
EOF
}
start() { mkconf "$1"; sudo ip netns exec "$1" "$OVPN" --config "$R/$1.conf" --daemon; }

# A client that never carries traffic does not need an interface, and without one it needs
# no namespace, address or veth either: it is a process and nothing else. That is what
# makes a thousand of them affordable. They still handshake and exchange keepalives, so
# each one is a real peer appearing in and disappearing from the driver's table.
#
# --inactive counts from process start, not from the tunnel coming up, and a dev null
# client has no tunnel traffic to reset it. So FLOOD_HOLD is the client's whole lifetime
# with the handshake inside it: near enough to a hold while handshakes take milliseconds,
# and useless when they take seconds, because then every client dies before it connects.
# A flood reporting almost no connects means the handshake time, not the flood.
mkflood() {
    cat > "$R/f$1.conf" <<EOF
client
dev null
proto udp4
remote $SERVER $PORT
nobind
ca $KEYS/ca.crt
cert $KEYS/client.crt
key $KEYS/client.key
remote-cert-tls server
data-ciphers AES-128-GCM
route-nopull
disable-dco
inactive $FLOOD_HOLD
verb 3
log-append $R/f$1.log
EOF
}

# A client on kernel DCO leaves its interface behind when killed, still carrying the
# address. The next openvpn then builds tun1 beside the stale tun0, so the namespace
# reads as connected while no handshake has completed: every swarm connect is counted
# and none of them happens. Delete what is left, so an address means what it says.
stop() {
    sudo ip netns pids "$1" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
    sudo ip netns exec "$1" sh -c 'for d in $(ls /sys/class/net | grep "^tun"); do ip link del "$d"; done' \
        >/dev/null 2>&1 || true
}

vpnip()  { sudo ip netns exec "$1" ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^tun/ {print $4}' | head -1 | cut -d/ -f1; }
waitup() { for _ in $(seq 1 40); do [ -n "$(vpnip "$1")" ] && return 0; sleep 0.5; done; return 1; }

# iperf3 scales its units, so a slow interval prints Kbits/sec and a fast one Gbits/sec.
# Matching only Mbits/sec read those as nothing, which showed up as a pair reporting 0.
mbits() {
    awk -v want="$1" '
        /receiver/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[KMG]?bits\/sec$/) {
                    v = $(i - 1)
                    if ($i == "bits/sec")  v /= 1000000
                    if ($i == "Kbits/sec") v /= 1000
                    if ($i == "Gbits/sec") v *= 1000
                    last = v; sum += v; n++
                }
            }
        }
        END { printf "%.1f", (want == "mean" ? (n ? sum / n : 0) : last + 0) }'
}

# last completed iperf3 throughput for a pair, in Mbit/s
throughput() { mbits last < "$R/$1.cli.log" 2>/dev/null; }

# mean over every completed iperf3 run for a pair
mean_throughput() { mbits mean < "$R/$1.cli.log" 2>/dev/null; }

add() { awk -v a="$1" -v b="$2" 'BEGIN {printf "%.1f", a + b}'; }

# Does the driver route into a peer's iroute subnet? Nothing else in the run reaches
# IPTrie::Find with entries present, and the trie is the code peers churn hardest.
#
# Every peer is given the same subnet, so whichever connected last owns it. Rather than
# guess, watch all of them and report which one the packet reaches.
check_iroute() {
    local from=$1 i ns dev got=""
    for i in $(seq 1 $NT); do
        ns=c$i
        [ "$ns" = "$from" ] && continue
        dev=$(sudo ip netns exec "$ns" sh -c 'ls /sys/class/net | grep "^tun" | head -1')
        [ -z "$dev" ] && continue
        sudo ip netns exec "$ns" timeout 8 tcpdump -i "$dev" -n -c 1 icmp \
            > "$R/iroute.$ns.txt" 2>&1 &
    done
    sleep 1
    sudo ip netns exec "$from" ping -c 6 -W 1 -q "$IROUTE_PROBE" >/dev/null 2>&1
    wait 2>/dev/null
    for i in $(seq 1 $NT); do
        ns=c$i
        grep -q "$IROUTE_PROBE" "$R/iroute.$ns.txt" 2>/dev/null && got=$ns
    done
    if [ -n "$got" ]; then
        echo "  iroute: $from -> $IROUTE_PROBE routed to $got"
        iroute_ok=1
    else
        echo "  iroute: $from -> $IROUTE_PROBE reached no peer"
    fi
}

echo "bringing up $NT traffic clients"
for i in $(seq 1 $NT); do start "c$i"; sleep 0.3; done
for i in $(seq 1 $NT); do
    waitup "c$i" && echo "  c$i = $(vpnip c$i)" || echo "  c$i failed to connect"
done

# Traffic between two clients hairpins through the server's host stack, which drops it
# unless that adapter forwards. Check it once here: without forwarding every pair reads
# as a stall for the whole run, and a stall is also what a driver fault looks like.
iroute_ok=0
[ "$NT" -ge 2 ] && check_iroute c1 c2

relay_ok=0
for p in $(seq 1 "$PAIRS"); do
    a=c$((p * 2 - 1)); b=c$((p * 2)); bip=$(vpnip "$b")
    [ -z "$bip" ] && { echo "  pair $p skipped (peer has no address)"; continue; }
    reachable=0
    for _ in $(seq 1 30); do
        if sudo ip netns exec "$a" ping -c1 -W2 -q "$bip" >/dev/null 2>&1; then
            reachable=1
            break
        fi
        sleep 1
    done
    if [ "$reachable" = 1 ]; then
        relay_ok=$((relay_ok + 1))
    else
        echo "  pair $p: $a cannot reach $b ($bip) after 30s - is forwarding on for the server adapter?"
    fi
    # disowned so the shell prints no job notice when they are killed at the end
    sudo ip netns exec "$b" sh -c "while true; do iperf3 -s -p 5201 >/dev/null 2>&1; sleep 1; done" &
    echo $! > "$R/$b.srv.pid"; disown %% 2>/dev/null || true
    sleep 1
    # The partner address is re-read every iteration rather than baked in, and the run is
    # bounded. A client that reconnects is given a new address from the pool, so a loop
    # holding the old one dials nobody; and iperf3 has no timeout of its own, so when
    # either end reconnects mid-test the TCP flow dies without an RST and iperf3 blocks on
    # it forever, never reaching the iteration that would pick the new address up. The
    # bound is generous: a -t 30 test whose setup is slow under the flood must finish,
    # because a killed run writes no result at all and the pair then reports nothing.
    echo "$bip" > "$R/$b.vpnip"
    sudo ip netns exec "$a" sh -c "while true; do bip=\$(cat '$R/$b.vpnip' 2>/dev/null); [ -n \"\$bip\" ] && timeout 90 iperf3 -c \"\$bip\" -p 5201 -t 30 >> '$R/$a.cli.log' 2>&1; sleep 2; done" &
    echo $! > "$R/$a.cli.pid"; disown %% 2>/dev/null || true
    echo "  pair $p: $a -> $b ($bip)"
done

# One independent loop per swarm client, so teardowns spread out rather than run in
# lockstep. `timeout` rather than `ping -w`: -w only accepts whole seconds and silently
# rejects a fractional hold, which would kill the client with nothing in flight.
# Counters are appended as they happen so progress can report real numbers.
swarm_loop() {
    local ns=$1 ok=0 fail=0
    while [ "$(date +%s)" -lt $END ]; do
        start "$ns"
        if waitup "$ns"; then
            ok=$((ok + 1))
            sudo ip netns exec "$ns" timeout "$HOLD" ping -f -q "$SERVER_TUN" >/dev/null 2>&1
        else
            fail=$((fail + 1))
            sleep 0.2
        fi
        echo "$ok $fail" > "$R/$ns.tally"
        stop "$ns"
        sleep 0.2
    done
}

tally() { cat "$R"/c*.tally 2>/dev/null | awk -v f="$1" '{s+=$f} END {print s+0}'; }

flood_pid=""
if [ "$FLOOD" -gt 0 ]; then
    echo "flood: $FLOOD per wave, ${FLOOD_HOLD}s after connecting, give up at ${FLOOD_GIVEUP}s, for ${DURATION}s"
    for i in $(seq 1 "$FLOOD"); do mkflood "$i"; done
    (
        while [ "$(date +%s)" -lt $END ]; do
            for i in $(seq 1 "$FLOOD"); do
                timeout "$FLOOD_GIVEUP" "$OVPN" --config "$R/f$i.conf" >/dev/null 2>&1 &
            done
            wait
            sleep 1
        done
    ) &
    flood_pid=$!
fi

echo "swarm: $SWARM clients, hold ${HOLD}s, for ${DURATION}s"
swarm_pids=""
for j in $(seq 1 "$SWARM"); do
    swarm_loop "c$((NT + j))" &
    swarm_pids="$swarm_pids $!"
done

printf '%6s  %8s  %8s  %8s  %-18s %s\n' \
    elapsed connects timeouts traffic per-pair 'total Mbit/s'
while [ "$(date +%s)" -lt $END ]; do
    sleep 30
    # Keep the partner addresses current, so a reconnect does not strand a pair.
    for p in $(seq 1 "$PAIRS"); do
        b=c$((p * 2)); ip=$(vpnip "$b")
        [ -n "$ip" ] && echo "$ip" > "$R/$b.vpnip"
    done
    up=0
    for i in $(seq 1 $NT); do [ -n "$(vpnip "c$i")" ] && up=$((up + 1)); done
    tp=""; total=0
    for p in $(seq 1 "$PAIRS"); do
        a=c$((p * 2 - 1))
        # A pair reports its last completed iperf3 run, which stands until the next one
        # finishes. Call it stale only after a couple of cycles with no new result: a
        # cycle is -t 30 plus a 2s sleep, longer than the 30s between samples, so a pair
        # that is working still skips a sample now and then.
        now=$(date +%s)
        n=$(grep -c receiver "$R/$a.cli.log" 2>/dev/null | head -1); n=${n:-0}
        eval "prev=\${seen_$p:-0}"
        eval "last=\${moved_$p:-$START}"
        if [ "$n" -gt "$prev" ]; then
            eval "moved_$p=$now"
            last=$now
        fi
        eval "seen_$p=$n"
        if [ "$n" -eq 0 ]; then
            v="-"
        elif [ "$((now - last))" -gt 90 ]; then
            v="stalled"
        else
            v=$(throughput "$a")
        fi
        tp="$tp ${v:-0}"
        case "$v" in stalled|-) ;; *) total=$(add "$total" "${v:-0}") ;; esac
    done
    printf '%5ds  %8s  %8s  %6s/%d  %-18s %s\n' \
        "$(( $(date +%s) - START ))" "$(tally 1)" "$(tally 2)" "$up" "$NT" "$tp" "$total"
done

# Wait only for the swarm loops. A bare `wait` would also block on the traffic pairs,
# which loop forever by design, and the run would never finish.
# shellcheck disable=SC2086
wait $swarm_pids
if [ -n "$flood_pid" ]; then
    kill "$flood_pid" 2>/dev/null
    pkill -f "$R/f[0-9]*.conf" 2>/dev/null
fi

for f in "$R"/*.pid; do [ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null; done
for i in $(seq 1 $((NT + SWARM))); do stop "c$i"; done

flood_ok=0
if [ "$FLOOD" -gt 0 ]; then
    flood_ok=$(grep -l "Initialization Sequence Completed" "$R"/f*.log 2>/dev/null |
        xargs -r grep -c "Initialization Sequence Completed" 2>/dev/null |
        awk -F: '{s += $NF} END {print s + 0}')
fi

ok=$(tally 1); fail=$(tally 2)
# grep -c already prints 0 when nothing matches, and still exits non-zero; an `|| echo 0`
# here appends a second line and breaks the arithmetic that consumes it.
count() { grep -c "$1" "$2" 2>/dev/null | head -1; }
samples=0; combined=0
for p in $(seq 1 "$PAIRS"); do
    a=c$((p * 2 - 1))
    samples=$((samples + $(count receiver "$R/$a.cli.log")))
    combined=$(add "$combined" "$(mean_throughput "$a")")
done

echo "logs kept in $OUTDIR"
# Client-side connect timeouts are a harness property, not a driver signal: OpenVPN
# handles handshakes serially, so a swarm arriving together overruns the client timeout
# long before the server is loaded. Cross-check against the server log.
printf '{"swarm_connects":%d,"swarm_timeouts":%d,"flood_connects":%d,"traffic_samples":%d,"traffic_mbit":%s,"relay_pairs":%d,"pairs":%d,"iroute_ok":%d,"outdir":"%s"}\n' \
    "$ok" "$fail" "$flood_ok" "$samples" "$combined" "$relay_ok" "$PAIRS" "$iroute_ok" "$OUTDIR"
