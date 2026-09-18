#!/bin/bash
# run-stress.sh --dut <ssh-target> --server-ip <ip> [--openvpn <path on the DUT>] [options]
#
# End-to-end run, driven from the Linux client host. Sets TestAeadUsageLimit and Driver
# Verifier on the device under test, runs the workload, collects logs and counters,
# prints a summary and a JSON verdict.
#
# Not run on the device under test: a detected fault bugchecks that machine, and a job
# running there would die with it and report nothing.
set -u

DUT=""; SERVER_IP=""; REMOTE_DIR='C:\ovpn-stress'
PAIRS=4; SWARM=16; DURATION=900; FLOOD=800
SKIP_ARM=0; OUTDIR=""
KEYS=${KEYS:-/usr/share/doc/openvpn/examples/sample-keys}
# empty means whatever Start-Server.ps1 defaults to, the installed openvpn
OPENVPN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dut)        DUT=$2; shift 2 ;;
        --server-ip)  SERVER_IP=$2; shift 2 ;;
        --remote-dir) REMOTE_DIR=$2; shift 2 ;;
        --pairs)      PAIRS=$2; shift 2 ;;
        --swarm)      SWARM=$2; shift 2 ;;
        --flood)      FLOOD=$2; shift 2 ;;
        --duration)   DURATION=$2; shift 2 ;;
        --keys)       KEYS=$2; shift 2 ;;
        --openvpn)    OPENVPN=$2; shift 2 ;;
        --outdir)     OUTDIR=$2; shift 2 ;;
        --skip-arm)   SKIP_ARM=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[ -z "$DUT" ] && { echo "--dut is required" >&2; exit 2; }

# --dut is the control path (SSH, may be an ssh_config alias); --server-ip is the data
# path the clients dial. They differ when control and data do not share a route: an ssh
# alias, a separate management NIC, or a public address in front of a private one.
# When --dut is already a bare address, default --server-ip to it.
# Only a bare IPv4 address is derivable. The rig is IPv4-only (both configs say udp4),
# and anything carrying a port or a hostname would not be valid in a client remote line.
if [ -z "$SERVER_IP" ]; then
    candidate=${DUT#*@}
    if echo "$candidate" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        SERVER_IP=$candidate
        echo "note: --server-ip defaulted to $SERVER_IP from --dut"
    else
        echo "--server-ip is required: '$DUT' is not a bare IPv4 address" >&2
        exit 2
    fi
fi

# The defaults are the configuration this was validated at. Past the ceiling below, the
# failures start coming from the rig rather than the driver: SSH to the device under test
# is in-band and heavy load starves it, and the client host runs out of room for iperf3
# flows.
if [ "$PAIRS" -gt 4 ] || [ "$SWARM" -gt 24 ] || [ "$FLOOD" -gt 1000 ]; then
    echo "WARNING: --pairs $PAIRS --swarm $SWARM --flood $FLOOD is beyond the validated"
    echo "         ceiling of 4, 24 and 1000."
    echo "         Expect harness failures, not driver findings."
fi

HERE=$(cd "$(dirname "$0")" && pwd)
CLIENTS=$((PAIRS * 2 + SWARM))
[ -z "$OUTDIR" ] && OUTDIR="$PWD/stress-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/run.log"
exec > >(tee -a "$LOG") 2>&1

dut_ps() { ssh "$DUT" "powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE_DIR\\$1" "${@:2}"; }

wait_for_dut() {
    local deadline=$(( $(date +%s) + ${1:-300} ))
    while [ "$(date +%s)" -lt $deadline ]; do
        ssh -o BatchMode=yes -o ConnectTimeout=5 "$DUT" 'echo up' 2>/dev/null | grep -q up && return 0
        sleep 5
    done
    return 1
}

# Absent or unreadable counts as zero: an unanswered GET_STATS must not abort the run
# under set -u before the verdict.
json_num() { echo "$1" | grep -o "\"$2\":[0-9.-]*" | head -1 | cut -d: -f2 | grep . || echo 0; }

fail() {
    echo
    echo "-- server log tail --"
    ssh "$DUT" "Get-Content \$env:TEMP\\ovpn-stress\\server.log -Tail 40" 2>/dev/null | tr -d '\r' | tee "$OUTDIR/server.log.tail"
    echo "-- a client log --"
    sudo tail -30 "$OUTDIR"/clients/c5.log 2>/dev/null || sudo tail -30 "$OUTDIR"/clients/c1.log 2>/dev/null
    echo "{\"verdict\":\"FAIL\",\"reason\":\"$1\",\"outdir\":\"$OUTDIR\"}"
    exit 1
}

echo "== results directory: $OUTDIR"

# The fault signal is "the DUT stopped answering", which is in-band: if SSH rides the same
# interface as the tunnel transport, heavy load can starve the control channel, which is
# indistinguishable from a bugcheck. Warn when they are not separated.
ctrl_addr=$(ssh "$DUT" \
    "(Get-NetTCPConnection -LocalPort 22 -State Established -ErrorAction SilentlyContinue | Select-Object -First 1).LocalAddress" \
    2>/dev/null | tr -d '\r ')
if [ -n "$ctrl_addr" ] && [ "$ctrl_addr" = "$SERVER_IP" ]; then
    echo "  WARNING: control and data share $ctrl_addr on the DUT."
    echo "           SSH competes with tunnel transport, so a starved control channel is"
    echo "           indistinguishable from a bugcheck. Prefer a separate management"
    echo "           interface, or an out-of-band console, for trustworthy fault detection."
elif [ -n "$ctrl_addr" ]; then
    echo "  control path $ctrl_addr, data path $SERVER_IP (separated)"
fi

echo "== staging scripts on $DUT"
for f in ca.crt server.crt server.key client.crt client.key; do
    [ -f "$KEYS/$f" ] || { echo "missing $f in $KEYS" >&2; exit 2; }
done
ssh "$DUT" "New-Item -ItemType Directory -Force '$REMOTE_DIR\\keys' | Out-Null"
scp -q "$HERE"/windows/*.ps1 "$DUT:$REMOTE_DIR/"
# the server reads its half from <remote-dir>\keys, so the Windows machine needs no
# key setup of its own
scp -q "$KEYS/ca.crt" "$KEYS/server.crt" "$KEYS/server.key" "$DUT:$REMOTE_DIR/keys/"
# the ETW profile lives at the repository root
[ -f "$HERE/../../ovpn-dco-win.wprp" ] && scp -q "$HERE/../../ovpn-dco-win.wprp" "$DUT:$REMOTE_DIR/"

if [ "$SKIP_ARM" -eq 0 ]; then
    echo "== setting TestAeadUsageLimit and Driver Verifier (reboot follows)"
    dut_ps 'Set-TestMode.ps1' -Arm | tr -d '\r'
    ssh "$DUT" 'shutdown /r /t 3' || true
    sleep 15
    wait_for_dut 420 || fail "device under test did not come back after the reboot"
fi
dut_ps 'Set-TestMode.ps1' -Show | tr -d '\r' | tee "$OUTDIR/testmode.txt"

# Baseline counters. They are cumulative since the driver loaded, so only a before/after
# delta says what this run did. Nothing holds the adapter yet, so GET_STATS may go
# unanswered; the deltas then lose their baseline, but the verdict comes from the server
# log.
echo "== baseline driver counters"
before=$(dut_ps 'Get-DcoStats.ps1' -AsJson | tr -d '\r')
echo "$before" > "$OUTDIR/driver-before.json"
if echo "$before" | grep -q '"ReceivedData"'; then
    echo "  $before"
else
    echo "  no counters: nothing holds the adapter yet, so the deltas below are absolute"
    before='{}'
fi

echo "== starting multipeer server"
# the remote side is PowerShell, so quote the path there: the default has a space in it
srv_args=(-Up)
[ -n "$OPENVPN" ] && srv_args+=(-OpenVpn "'$OPENVPN'")
dut_ps 'Start-Server.ps1' "${srv_args[@]}" | tr -d '\r' || fail "server failed to start"

echo "== building $CLIENTS client namespaces"
DUT="$SERVER_IP" "$HERE/linux/setup-clients.sh" "$CLIENTS" || fail "client namespace setup failed"

# Nothing in OVPN_STATS counts rotations or decryption failures, so capture the driver's
# own events for the whole workload. Detached for the same reason as the sampler above.
# Clear the previous run's file first: the collector below would otherwise fetch it at
# once and report the last run's numbers as this one's.
ssh "$DUT" "Remove-Item '$REMOTE_DIR\\rotations.json','$REMOTE_DIR\\throughput.csv' -ErrorAction SilentlyContinue" 2>/dev/null
ssh "$DUT" "\$c = 'cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE_DIR\\Get-EpochRotations.ps1 -Seconds $DURATION -OutFile $REMOTE_DIR\\rotations.json'; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = \$c } | Out-Null" \
    2>/dev/null || echo "  note: could not start the ETW capture"

# Detached, writing to a file on the device. The SSH it used to stream over is the first
# thing heavy load starves, and the sampler died with it.
ssh "$DUT" "\$c = 'cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE_DIR\\Measure-Throughput.ps1 -Seconds $DURATION -Interval 5 > $REMOTE_DIR\\throughput.csv 2>&1'; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = \$c } | Out-Null" \
    2>"$OUTDIR/throughput.err" || echo "  note: could not start the throughput sampler"

echo "== running workload (${DURATION}s)"
summary=$("$HERE/linux/swarm.sh" --server "$SERVER_IP" --pairs "$PAIRS" --swarm "$SWARM" \
             --flood "$FLOOD" --duration "$DURATION" --keys "$KEYS" --outdir "$OUTDIR" |
             tee /dev/stderr | tail -1)

echo "== collecting results"
# A bugcheck shows up as the DUT no longer answering; that is the primary fault signal.
wait_for_dut 60 || fail "device under test stopped responding (bugcheck)"

server_status=$(dut_ps 'Start-Server.ps1' -Status | tr -d '\r')
ssh "$DUT" "Get-Content \$env:TEMP\\ovpn-stress\\server.log" 2>/dev/null | tr -d '\r' > "$OUTDIR/server.log"
dut_ps 'Start-Server.ps1' -Down >/dev/null
# scp will not take the backslashes, so ask for the same directory with forward slashes
REMOTE_FWD=$(echo "$REMOTE_DIR" | tr '\\' '/')
scp -q "$DUT:$REMOTE_FWD/throughput.csv" "$OUTDIR/throughput.csv" 2>/dev/null ||
    echo "  note: no throughput samples collected"
# the capture needs a moment past the workload to decode its trace
for _ in $(seq 1 30); do
    scp -q "$DUT:$REMOTE_FWD/rotations.json" "$OUTDIR/rotations.json" 2>/dev/null && break
    sleep 5
done
after=$(dut_ps 'Get-DcoStats.ps1' -AsJson | tr -d '\r')
echo "$after" > "$OUTDIR/driver-after.json"

"$HERE/linux/teardown-clients.sh" "$CLIENTS" >/dev/null

# Pool tracking only reports at unload, so unload it. If the driver left allocations
# behind, Verifier bugchecks here and the machine stops answering, which is the same
# signal as any other fault.
echo "== unloading the driver to check for leaked pool"
pool_before=$(ssh "$DUT" "(Get-Counter '\\Memory\\Pool Nonpaged Bytes').CounterSamples[0].CookedValue" 2>/dev/null | tr -d '\r ')
ssh "$DUT" "Get-PnpDevice -FriendlyName '*Data Channel Offload*' | Disable-PnpDevice -Confirm:\$false; Start-Sleep 3; Get-PnpDevice -FriendlyName '*Data Channel Offload*' | Enable-PnpDevice -Confirm:\$false" >/dev/null 2>&1
sleep 5
wait_for_dut 90 || fail "device under test stopped responding while unloading the driver (leaked pool?)"
pool_after=$(ssh "$DUT" "(Get-Counter '\\Memory\\Pool Nonpaged Bytes').CounterSamples[0].CookedValue" 2>/dev/null | tr -d '\r ')
[ "$SKIP_ARM" -eq 0 ] && dut_ps 'Set-TestMode.ps1' -Disarm >/dev/null

rotations=$(cat "$OUTDIR/rotations.json" 2>/dev/null || echo '{}')
read -r rx_mean rx_peak tx_mean tx_peak cpu_mean cpu_peak <<<"$(awk -F, 'NR > 1 && NF == 4 {
        n++
        rx += $2; if ($2 > rxpeak) rxpeak = $2
        tx += $3; if ($3 > txpeak) txpeak = $3
        cpu += $4; if ($4 > cpupeak) cpupeak = $4
    } END {if (n) printf "%.0f %.0f %.0f %.0f %.0f %.0f",
                       rx / n, rxpeak, tx / n, txpeak, cpu / n, cpupeak}' \
    "$OUTDIR/throughput.csv" 2>/dev/null)"
peers=$(echo "$server_status" | grep -o 'MULTI: Learn): [0-9]*' | grep -o '[0-9]*$')
errors=$(echo "$server_status" | grep -o 'errors: [0-9]*' | grep -o '[0-9]*$')
churn=$(echo "$server_status" | grep -o 'churn: [0-9]*' | grep -o '[0-9]*$')
exited=$(echo "$server_status" | grep -o 'server exited: [0-9]*' | grep -o '[0-9]*$')
drops=$(echo "$server_status" | grep -o 'dropped sends: [0-9]*' | grep -o '[0-9]*$')
relay=$(json_num "$summary" relay_pairs)

d_lost_in=$(( $(json_num "$after" LostInData) - $(json_num "$before" LostInData) ))
decrypt_errors=$(json_num "$rotations" DecryptErrors)
d_lost_out=$(( $(json_num "$after" LostOutData) - $(json_num "$before" LostOutData) ))
d_recv=$(( $(json_num "$after" ReceivedData) - $(json_num "$before" ReceivedData) ))
d_bytes=$(( $(json_num "$after" TransportBytesSent) - $(json_num "$before" TransportBytesSent) ))

echo
echo "================ summary ================"
printf '  %-26s %s\n' "peer sessions (server)"   "${peers:-?}"
printf '  %-26s %s\n' "server errors (expected)" "${errors:-?}"
printf '  %-26s %s\n' "server churn (expected)"  "${churn:-?}"
printf '  %-26s %s\n' "server dropped sends"     "${drops:-?}"
printf '  %-26s %s\n' "server exited"            "${exited:-?}"
printf '  %-26s %s / %s\n' "relaying pairs"      "${relay:-0}" "$PAIRS"
printf '  %-26s %s\n' "iroute reachable"         "$(json_num "$summary" iroute_ok)"
printf '  %-26s %s in, %s handed over\n' "route trie inserts" \
       "$(json_num "$rotations" IrouteAdds)" "$(json_num "$rotations" TrieHandovers)"
printf '  %-26s %s by userspace, %s by peer teardown\n' "route trie removals" \
       "$(json_num "$rotations" IrouteDels)" "$(json_num "$rotations" TrieRemovals)"
printf '  %-26s %s\n' "swarm connects"           "$(json_num "$summary" swarm_connects)"
printf '  %-26s %s\n' "swarm timeouts"           "$(json_num "$summary" swarm_timeouts)"
printf '  %-26s %s\n' "flood connects"           "$(json_num "$summary" flood_connects)"
printf '  %-26s %s\n' "traffic samples"          "$(json_num "$summary" traffic_samples)"
printf '  %-26s %s\n' "packets relayed"          "$d_recv"
printf '  %-26s %s MB\n' "bytes relayed"         "$(( d_bytes / 1048576 ))"
printf '  %-26s %s mean, %s peak\n' "server Mbit/s in"  "${rx_mean:-?}" "${rx_peak:-?}"
printf '  %-26s %s mean, %s peak\n' "server Mbit/s out" "${tx_mean:-?}" "${tx_peak:-?}"
printf '  %-26s %s%% mean, %s%% peak\n' "server CPU"      "${cpu_mean:-?}" "${cpu_peak:-?}"
printf '  %-26s %s\n' "client iperf3 Mbit/s"     "$(json_num "$summary" traffic_mbit)"
printf '  %-26s %s\n' "epoch rotations (recv)"   "$(json_num "$rotations" RecvRotations)   <- must be > 0"
printf '  %-26s %s (mostly peer setup)\n' "epoch key derivations" \
       "$(json_num "$rotations" KeyDerivations)"
printf '  %-26s %s (epoch window %s, replay %s)\n' "decrypt errors" "${decrypt_errors:-?}" \
       "$(json_num "$rotations" UnknownEpoch)" "$(json_num "$rotations" InvalidPacketId)"
printf '  %-26s %s\n' "LostInData (delta)"       "$d_lost_in"
printf '  %-26s %s\n' "LostOutData (delta)"      "$d_lost_out"
printf '  %-26s %s MB -> %s MB\n' "nonpaged pool" \
       "$(( ${pool_before:-0} / 1048576 ))" "$(( ${pool_after:-0} / 1048576 ))"
echo "  logs: $OUTDIR"
echo "========================================="

# Throughput is not gated: it varies by a factor of two between runs even on an idle
# machine, and the client host is usually the limit rather than the driver.
# Decryption failures are reported, not gated. TestAeadUsageLimit rotates epoch keys
# thousands of times a minute, far faster than anything real, and most of these are a
# sender running past the four future keys the receiver holds. Until each cause is
# characterised at a realistic rotation rate, failing on the total would fail every run
# for something the driver is not responsible for.
[ "${peers:-0}" -eq 0 ] && fail "no peer ever connected"
# The churn is half the workload. Past a few dozen swarm clients the server, which
# handles handshakes one at a time, cannot complete any inside the client timeout, and a
# run where none connected has not tested the churn at all.
[ "$(json_num "$summary" swarm_connects)" = "0" ] && fail "no swarm client ever connected: lower --swarm"
[ "${relay:-0}" -ne "$PAIRS" ] && fail "only ${relay:-0} of $PAIRS pairs could reach their partner"
# Rotations, not derivations. A key is derived six times per peer session before any
# traffic moves -- send, receive and four future keys -- so with a flood of short-lived
# peers the derivation count is large whether or not a single epoch ever rotated. What
# proves rotation happened is the receiver seeing an epoch it had not seen before.
rotations_seen=$(json_num "$rotations" RecvRotations)
[ "${rotations_seen:-0}" = "0" ] &&
    fail "no epoch rotation was observed, or the sampler never reported: are the clients negotiating epoch data keys?"
if [ "${exited:-0}" != "0" ]; then
    echo
    echo "  The OpenVPN server exited, which disconnected every client. A data key was"
    echo "  installed for a peer the driver had just expired: the driver owns the keepalive"
    echo "  timer, deletes the peer itself and reports it asynchronously, so userspace can"
    echo "  be a couple of milliseconds behind. Refusing the key is correct; treating the"
    echo "  refusal as fatal for the whole process instead of for that one client is not."
    echo
    echo "  This is an OpenVPN bug rather than a driver bug, and the run fails on it either"
    echo "  way. To confirm which peer, look for 'Peer not found' from OvpnPeerNewKeyV2 in"
    echo "  a trace taken with Trace-Events.ps1."
    fail "the OpenVPN server exited (peer expired between delete and key install)"
fi

# Loose bounds: these catch gross breakage, not regressions. Throughput and churn both
# vary by a factor of two between runs, so a tight bound would flap and be ignored.
# Ratios rather than counts, because both scale with the load.
if [ "${d_recv:-0}" -gt 10000 ]; then
    [ "$(( ${d_lost_in:-0} * 100 / d_recv ))" -ge 1 ] &&
        fail "LostInData is ${d_lost_in} of ${d_recv} received, over 1%: peers are disappearing under traffic faster than churn accounts for"
    [ "$(( ${decrypt_errors:-0} * 100 / d_recv ))" -ge 5 ] &&
        fail "decrypt errors are ${decrypt_errors} of ${d_recv} received, over 5%: rotation is losing packets, not just outrunning the key window"
fi

[ "${d_recv:-0}" -lt 10000 ] && fail "only ${d_recv:-0} data packets were received: the workload did not run"

# Not gated: a multipeer server under this churn logs per-client errors routinely, a key
# install refused for an expired peer among them. The server exiting is what fails a run,
# and that is gated above.
echo "{\"verdict\":\"PASS\",\"outdir\":\"$OUTDIR\"}"
