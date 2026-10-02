# Sourced by start-server.sh and start-client.sh.
#
# A tunnel reaches its ovpn device as one outer flow, so every decrypted packet, and
# every send its ACKs trigger, would run on the one core that received it, capping
# Linux's end well below the driver. RPS spreads them by inner flow over all CPUs.
set_rps() {
    local n mask="" bits q
    n=$(nproc)
    while [ "$n" -gt 0 ]; do
        bits=$(( n >= 32 ? 32 : n ))
        mask="$(printf '%08x' $(( (1 << bits) - 1 )))${mask:+,$mask}"
        n=$(( n - bits ))
    done
    for q in /sys/class/net/"$1"/queues/rx-*; do
        echo "$mask" | sudo tee "$q/rps_cpus" >/dev/null || return 1
    done
    echo "rps on $1: $mask"
}
