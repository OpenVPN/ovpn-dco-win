#!/bin/bash
# run-perf.sh --dut <ssh-target> [--mode client|server] [--proto udp|tcp]
#             [--peer linux|<ssh-target>] [--server-ip <ip>] [--seconds 30] [--runs 3]
#             [--streams "1 4"] [--min-mbit 1500] [--markdown <file>]
#             [--keys <dir>] [--iperf3 <path on Windows>] [--outdir <dir>]
#
# Throughput of the driver under test, in both directions.
#
#   client mode   the Windows machine is a point-to-point client and the other end is a
#                 Linux server. This is how the driver ships, and the only mode in which
#                 it speaks TCP: its socket, Tcp flag and reassembly state are one per
#                 device, so a multipeer server has nowhere to put a second connection.
#
#   server mode   the Windows machine is a multipeer server. UDP only, for the same
#                 reason. --peer says what carries the client: linux, which keeps the far
#                 end off the critical path, or a second Windows machine, which measures
#                 the driver at both ends at once.
#
# A Linux end runs the in-tree ovpn module, so it offloads too and the number stays about
# the driver rather than about userspace crypto on the other side.
#
# Unlike the stress rig this needs a release driver with Driver Verifier off and no
# TestAeadUsageLimit: special pool taxes every allocation, WPP traces the data path, and
# a forced rotation every few thousand packets burns CPU no real deployment spends.
set -u

DUT=""; SERVER_IP=""; MODE=client; PROTO=udp; PEER=linux
SECONDS_PER=30; RUNS=3; STREAMS="1 4"
REMOTE_DIR='C:\ovpn-perf'; OUTDIR=""; PORT=11198
KEYS=${KEYS:-/usr/share/doc/openvpn/examples/sample-keys}
IPERF3='C:\stage\iperf3.exe'
MARKDOWN=''
# Not a performance target: a floor that catches a halving rather than a wobble. The
# lowest median measured across the tests is about 2100 Mbit/s, so this leaves room for
# the run-to-run spread these instances have and still fails a real collapse.
MIN_MBIT=1500
SERVER_TUN=10.88.0.1

while [ $# -gt 0 ]; do
    case "$1" in
        --dut)        DUT=$2; shift 2 ;;
        --server-ip)  SERVER_IP=$2; shift 2 ;;
        --mode)       MODE=$2; shift 2 ;;
        --proto)      PROTO=$2; shift 2 ;;
        --peer)       PEER=$2; shift 2 ;;
        --seconds)    SECONDS_PER=$2; shift 2 ;;
        --runs)       RUNS=$2; shift 2 ;;
        --streams)    STREAMS=$2; shift 2 ;;
        --port)       PORT=$2; shift 2 ;;
        --keys)       KEYS=$2; shift 2 ;;
        --iperf3)     IPERF3=$2; shift 2 ;;
        --min-mbit)   MIN_MBIT=$2; shift 2 ;;
        --markdown)   MARKDOWN=$2; shift 2 ;;
        --remote-dir) REMOTE_DIR=$2; shift 2 ;;
        --outdir)     OUTDIR=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -z "$DUT" ] && [ "$MODE" != baseline ] && { echo "--dut is required" >&2; exit 2; }
case "$PROTO" in
    udp|tcp) ;;
    *) echo "--proto must be udp or tcp" >&2; exit 2 ;;
esac
case "$MODE" in
    client)
        [ "$PEER" = linux ] ||
            { echo "client mode always has a Linux server; --peer is for server mode" >&2; exit 2; }
        ;;
    server)
        [ "$PROTO" = tcp ] &&
            { echo "the driver speaks TCP point to point only" >&2; exit 2; }
        ;;
    baseline)
        # No Windows machine at all: the control that says what the hardware and the
        # in-kernel module can do, so a driver number can be read as a fraction of it.
        if [ -z "$PEER" ] || [ "$PEER" = linux ]; then
            echo "baseline mode needs --peer <ssh-target> for the second Linux machine" >&2
            exit 2
        fi
        ;;
    *) echo "--mode must be client, server or baseline" >&2; exit 2 ;;
esac

# Which machine runs which half. "local" is this machine.
if [ "$MODE" = client ]; then
    SRV_HOST=local; SRV_OS=linux
    CLI_HOST=$DUT;  CLI_OS=windows
elif [ "$MODE" = baseline ]; then
    SRV_HOST=$PEER; SRV_OS=linux
    CLI_HOST=local; CLI_OS=linux
else
    SRV_HOST=$DUT;  SRV_OS=windows
    if [ "$PEER" = linux ]; then
        CLI_HOST=local; CLI_OS=linux
    else
        CLI_HOST=$PEER; CLI_OS=windows
    fi
fi

# The name the README uses for this combination, so a result says what it is.
if [ "$MODE" = baseline ]; then
    TEST=perf-linux-linux-$PROTO
elif [ "$MODE" = client ]; then
    TEST=perf-client-$PROTO
elif [ "$PEER" = linux ]; then
    TEST=perf-server-$PROTO
else
    TEST=perf-win-win-$PROTO
fi

[ -z "$OUTDIR" ] && OUTDIR="$PWD/perf-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
HERE=$(cd "$(dirname "$0")" && pwd)

fail() { echo "{\"verdict\":\"FAIL\",\"reason\":\"$1\",\"outdir\":\"$OUTDIR\"}"; exit 1; }

# Run a command on either end; "local" means here.
on() { h=$1; shift; if [ "$h" = local ]; then sh -c "$*"; else ssh "$h" "$*"; fi; }
ps_on() { h=$1; s=$2; shift 2; ssh "$h" "powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE_DIR\\$s" "$@"; }
iperf_bin() { if [ "$1" = windows ]; then echo "$IPERF3"; else echo iperf3; fi; }

# The linux/ scripts run on whichever machine carries that end, so a remote Linux end
# gets them copied across first, the same way a Windows end does.
linux_stage() {   # <ssh-target>
    [ "$1" = local ] && return 0
    ssh "$1" 'mkdir -p ~/perf-rig-linux'
    scp -q "$HERE"/linux/*.sh "$1:perf-rig-linux/"
    ssh "$1" 'chmod +x ~/perf-rig-linux/*.sh'
}
linux_run() {     # <host> <script> <args...>
    h=$1; sc=$2; shift 2
    if [ "$h" = local ]; then "$HERE/linux/$sc" "$@"; else ssh "$h" "~/perf-rig-linux/$sc $*"; fi
}

# The address the client dials: this machine in client mode, the Windows server in
# server mode, and the far Linux machine in baseline mode. Each knows its own best.
if [ -z "$SERVER_IP" ]; then
    case "$MODE" in
        client)   SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}') ;;
        baseline) SERVER_IP=$(ssh "$PEER" "ip route get 1.1.1.1 | awk '{print \$7; exit}'" 2>/dev/null) ;;
        *)        SERVER_IP=$(ssh "$DUT" "(Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway -ne \$null } | Select-Object -First 1).IPv4Address.IPAddress" 2>/dev/null | tr -d ' ') ;;
    esac
fi
[ -z "$SERVER_IP" ] && { echo "could not work out --server-ip" >&2; exit 2; }

stage_windows() {   # <ssh-target> <server|client>
    for f in ca.crt "$2.crt" "$2.key"; do
        [ -f "$KEYS/$f" ] || { echo "missing $f in $KEYS" >&2; exit 2; }
    done
    ssh "$1" "New-Item -ItemType Directory -Force '$REMOTE_DIR\\keys' | Out-Null"
    scp -q "$HERE"/windows/*.ps1 "$1:$REMOTE_DIR/"
    # Set-TestMode, Get-NicResets and Get-DcoStats belong to the stress rig and are reused.
    scp -q "$HERE"/../stress/windows/Set-TestMode.ps1 \
           "$HERE"/../stress/windows/Get-NicResets.ps1 \
           "$HERE"/../stress/windows/Get-DcoStats.ps1 "$1:$REMOTE_DIR/"
    scp -q "$KEYS/ca.crt" "$KEYS/$2.crt" "$KEYS/$2.key" "$1:$REMOTE_DIR/keys/"
}

# A run that measured a checked build, or one with Verifier armed, reports a number a
# factor low and looks exactly like a regression. Refuse rather than mislead. With
# Windows at both ends either one can spoil the measurement, so both are checked.
check_windows() {   # <ssh-target>
    v=$(ssh "$1" 'verifier /query 2>&1 | Select-String "MODULE" | Measure-Object | Select-Object -ExpandProperty Count' 2>/dev/null | tr -d '\r ')
    [ "${v:-0}" != "0" ] && fail "Driver Verifier is armed on $1: run Set-TestMode.ps1 -Disarm and reboot"
    k=$(ps_on "$1" 'Set-TestMode.ps1' -Show 2>/dev/null | tr -d '\r' | grep -i 'TestAeadUsageLimit' | head -1)
    case "$k" in
        *"(not set)"*|"") ;;
        *) fail "TestAeadUsageLimit is set on $1: rotation will cost throughput" ;;
    esac
}

echo "== staging"
[ "$SRV_OS" = windows ] && stage_windows "$SRV_HOST" server
[ "$CLI_OS" = windows ] && stage_windows "$CLI_HOST" client
[ "$SRV_OS" = linux ] && linux_stage "$SRV_HOST"
[ "$CLI_OS" = linux ] && linux_stage "$CLI_HOST"

echo "== checking the machines are set up for measurement"
[ "$SRV_OS" = windows ] && check_windows "$SRV_HOST"
[ "$CLI_OS" = windows ] && check_windows "$CLI_HOST"

echo "== starting the $SRV_OS server"
if [ "$SRV_OS" = linux ]; then
    linux_run "$SRV_HOST" start-server.sh --proto "$PROTO" --port "$PORT" ||
        fail "the Linux server did not start"
else
    # The status has to come from the script, not from the tr that tidies its output:
    # a pipeline reports the last command, so piping first swallows the failure.
    out=$(ps_on "$SRV_HOST" 'Start-Server.ps1' -Up -Port "$PORT" 2>&1) ||
        { echo "$out" | tr -d '\r'; fail "the Windows server did not start"; }
    echo "$out" | tr -d '\r'
fi

echo "== starting the $CLI_OS client"
if [ "$CLI_OS" = linux ]; then
    linux_run "$CLI_HOST" start-client.sh --server "$SERVER_IP" --port "$PORT" ||
        fail "the Linux client did not connect"
else
    out=$(ps_on "$CLI_HOST" 'Start-Client.ps1' -Up -Server "$SERVER_IP" -Port "$PORT" -Proto "$PROTO" \
              -CertDir "$REMOTE_DIR\\keys" 2>&1) ||
        { echo "$out" | tr -d '\r'; fail "the Windows client did not connect"; }
    echo "$out" | tr -d '\r'
fi

# The first flow otherwise times out while the route and the peer settle, and a failed
# connect reads as nought Mbit/s rather than as a rig that started too early.
if [ "$CLI_OS" = windows ]; then
    probe="ping -n 1 -w 1000 $SERVER_TUN"
else
    probe="ping -c 1 -W 1 $SERVER_TUN"
fi
for _ in $(seq 1 20); do
    on "$CLI_HOST" "$probe" >/dev/null 2>&1 && break
    sleep 1
done
on "$CLI_HOST" "$probe" >/dev/null 2>&1 ||
    fail "the tunnel came up but the client cannot reach $SERVER_TUN"

# iperf3 runs from the client end so that both directions share one control connection:
# forward is client to server, and -R is server to client. They are different paths in
# the driver, encrypt-and-send against receive-and-decrypt, so they are reported apart.
# The traffic inside the tunnel is TCP either way: --proto is the tunnel transport, and
# TCP goodput is what a user gets. -O skips slow start, which otherwise drags a short run
# by a different amount each time. Both stream counts are measured because the comparison
# is the diagnostic: this driver has one queue and no RSS, so -P 4 running far ahead of
# -P 1 means the single flow was limited somewhere else, not by the driver.
# -O omits the head of the run from the result rather than extending it, so a short run
# with the default omit reports a window of a second or two and swings by 50%. Scale it,
# and say what was actually measured.
OMIT=3
[ "$SECONDS_PER" -lt 10 ] && OMIT=1
WINDOW=$(( SECONDS_PER - OMIT ))
[ "$WINDOW" -lt 5 ] &&
    echo "  WARNING: measuring a ${WINDOW}s window, which swings widely; --seconds 30 is the default for a reason"
echo "== measuring $RUNS runs of ${SECONDS_PER}s each way (${WINDOW}s measured), streams:$STREAMS"
# The Cygwin iperf3 build takes -D and then exits, leaving nothing listening, so the
# Windows server is started the way the rest of the Windows side is.
if [ "$SRV_OS" = windows ]; then
    ssh "$SRV_HOST" "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = \"$IPERF3 -s -p 5202\" } | Out-Null"
else
    on "$SRV_HOST" "iperf3 -s -p 5202 -D"
fi
for p in $STREAMS; do
    for i in $(seq 1 "$RUNS"); do
        for dir in forward reverse; do
            flag=""; [ "$dir" = reverse ] && flag="-R"
            # iperf3 reports a lost control socket as a result like any other, and it
            # parses as nought Mbit/s. Retry once, then leave the run out rather than
            # let a failed measurement drag the median.
            for try in 1 2; do
                out=$(on "$CLI_HOST" "$(iperf_bin "$CLI_OS") -c $SERVER_TUN -p 5202 -t $SECONDS_PER -O $OMIT -P $p -J $flag" 2>/dev/null)
                err=$(echo "$out" | grep -o '"error":[[:space:]]*"[^"]*"' |
                      sed 's/.*"error":[[:space:]]*"//; s/"$//')
                [ -z "$err" ] && break
            done
            if [ -n "$err" ]; then
                echo "  -P$p run $i $dir: failed, $err"
                continue
            fi
            echo "$out" > "$OUTDIR/iperf-$dir-p$p-$i.json"
            mbit=$(echo "$out" | tr -d ' \t' |
                   grep -o '"bits_per_second":[0-9.]*' | tail -1 | cut -d: -f2 |
                   awk '{printf "%.0f", $1 / 1000000}')
            echo "  -P$p run $i $dir: ${mbit:-0} Mbit/s"
        done
    done
done
if [ "$SRV_OS" = windows ]; then
    ssh "$SRV_HOST" "taskkill /F /IM iperf3.exe" >/dev/null 2>&1
else
    on "$SRV_HOST" "pkill -f 'iperf3 -s -p 5202'" >/dev/null 2>&1
fi

median() {
    for f in "$OUTDIR"/iperf-$1-p$2-*.json; do
        [ -f "$f" ] || continue
        tr -d ' \t' < "$f" | grep -o '"bits_per_second":[0-9.]*' | tail -1 | cut -d: -f2
    done | awk '{print $1 / 1000000}' | sort -n |
        awk '{v[NR]=$1} END {if (NR) printf "%.0f", (NR % 2) ? v[(NR+1)/2] : (v[NR/2] + v[NR/2+1]) / 2}'
}

# An adapter that went down mid-measurement drags an average without any other sign.
nic_resets() {
    n=$(ps_on "$1" 'Get-NicResets.ps1' -Minutes $(( (SECONDS_PER * RUNS * 4 + 300) / 60 )) 2>/dev/null |
        tr -d '\r' | grep -oE 'minutes: [0-9]+' | grep -oE '[0-9]+$')
    echo "${n:-0}"
}
resets=0
[ "$SRV_OS" = windows ] && resets=$(( resets + $(nic_resets "$SRV_HOST") ))
[ "$CLI_OS" = windows ] && resets=$(( resets + $(nic_resets "$CLI_HOST") ))

# The driver device takes one handle, so a stats query loses to a running peer. The
# counters outlive it, so read them once it has gone.
if [ "$CLI_OS" = linux ]; then
    linux_run "$CLI_HOST" start-client.sh --stop >/dev/null 2>&1
else
    ps_on "$CLI_HOST" 'Start-Client.ps1' -Down >/dev/null 2>&1
    ps_on "$CLI_HOST" 'Get-DcoStats.ps1' -AsJson 2>/dev/null | tr -d '\r' > "$OUTDIR/driver-stats-client.json"
fi
if [ "$SRV_OS" = linux ]; then
    linux_run "$SRV_HOST" start-server.sh --stop >/dev/null 2>&1
else
    ps_on "$SRV_HOST" 'Start-Server.ps1' -Down >/dev/null 2>&1
    ps_on "$SRV_HOST" 'Get-DcoStats.ps1' -AsJson 2>/dev/null | tr -d '\r' > "$OUTDIR/driver-stats-server.json"
fi

echo
echo "================ summary ================"
printf '  %-38s %s\n' "test" "$TEST"
printf '  %-38s %s\n' "ends" "$SRV_OS server, $CLI_OS client"
for p in $STREAMS; do
    printf '  %-38s %s\n' "$CLI_OS client -> $SRV_OS server (-P$p)" "$(median forward "$p") Mbit/s"
    printf '  %-38s %s\n' "$SRV_OS server -> $CLI_OS client (-P$p)" "$(median reverse "$p") Mbit/s"
done
printf '  %-38s %s\n' "NIC resets" "$resets"
echo "  logs: $OUTDIR"
echo "========================================="

# One row per stream count, appended so a workflow can collect every test into one
# table. The direction columns name the machines, because which end Windows is flips
# with the mode.
# A row below the floor is the reason the run failed, so say so in the table rather
# than leaving it to look like any other number.
mbit_cell() { if [ "${1:-0}" -lt "$MIN_MBIT" ]; then echo "$1 Mbit/s **below floor**"; else echo "$1 Mbit/s"; fi; }
if [ -n "$MARKDOWN" ]; then
    [ -f "$MARKDOWN" ] ||
        printf "| test | ends | streams | client -> server | server -> client |\n|---|---|---|---|---|\n" > "$MARKDOWN"
    for p in $STREAMS; do
        printf "| %s | %s server, %s client | -P%s | %s | %s |\n" \
            "$TEST" "$SRV_OS" "$CLI_OS" "$p" \
            "$(mbit_cell "$(median forward "$p")")" "$(mbit_cell "$(median reverse "$p")")" >> "$MARKDOWN"
    done
fi

[ "$resets" != "0" ] &&
    fail "a machine reset its NIC ${resets} time(s) while measuring: the numbers are not comparable"

first=$(echo $STREAMS | awk '{print $1}')
[ "$(median forward "$first")" = "" ] && fail "no throughput was measured"

# A floor, not a target. Every median has to clear it, so a collapse in one direction
# or at one stream count is not hidden by the others.
for p in $STREAMS; do
    for dir in forward reverse; do
        m=$(median "$dir" "$p")
        [ "${m:-0}" -lt "$MIN_MBIT" ] &&
            fail "$dir at -P$p measured ${m:-0} Mbit/s, below the ${MIN_MBIT} Mbit/s floor"
    done
done

echo "{\"verdict\":\"PASS\",\"test\":\"$TEST\",\"forward_mbit\":$(median forward "$first"),\"reverse_mbit\":$(median reverse "$first"),\"outdir\":\"$OUTDIR\"}"