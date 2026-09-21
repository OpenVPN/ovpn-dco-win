# ovpn-dco-win perf rig

Throughput of the driver under test, in both directions. The far end is normally Linux
running the in-tree `ovpn` module, so both ends offload the data channel and the number
is about the driver rather than about userspace crypto on the other side.

Two machines, the same pair the stress rig uses, and a third for the Windows-to-Windows
test. What differs is the Windows configuration: perf needs a **release** driver with
**Driver Verifier off** and no `TestAeadUsageLimit`. Special pool taxes every allocation,
WPP traces the data path, and a forced key rotation every few thousand packets costs CPU
that no real deployment spends. A run refuses to start if it finds either, because the
result would look like a regression rather than a misconfiguration.

## The tests

| name | Windows role | other end | transport |
| --- | --- | --- | --- |
| `perf-client-udp` | point-to-point client | Linux server | UDP |
| `perf-client-tcp` | point-to-point client | Linux server | TCP |
| `perf-server-udp` | multipeer server | Linux client | UDP |
| `perf-win-win-udp` | multipeer server | Windows client | UDP |
| `perf-linux-linux-udp` | none | Linux both ends | UDP |

`perf-linux-linux-udp` involves no Windows machine at all. It is the control: two Linux
ends on the same hardware say what the network and the in-kernel module can do between
them, so a driver number can be read as a fraction of what was achievable rather than
as a bare figure. It never says anything about the driver, and a drop in it is news
about the instances rather than about this repository.

There is no `perf-server-tcp`. The driver's socket, its `Tcp` flag and its stream
reassembly state are one per device, so a multipeer server has nowhere to keep a second
connection: TCP is point to point only.

Client mode is how the driver ships, behind OpenVPN GUI and Connect, and is the only mode
that reaches the TCP transport or the point-to-point ioctls. Server mode measures the
multipeer path the stress rig exercises for correctness.

A Linux far end is the better measurement, and the default, because it keeps the other
end off the critical path: whatever the number is, it is the driver's. Windows at both
ends measures the driver twice at once, so the slower end caps the result and the report
cannot say which one it was. It is worth running because it is a real deployment — site
to site — and not because it isolates anything. `perf-win-win-udp` is spelled
`--mode server --peer <ssh-target>`, the peer being that second Windows machine.

## Running

From the Linux machine:

```sh
tests/perf/run-perf.sh --dut <ssh-target> \
    [--mode client|server|baseline] [--proto udp|tcp] [--peer linux|<ssh-target>] \
    [--seconds 30] [--runs 3] [--streams "1 4"] [--outdir <dir>]
```

`--dut` is the Windows machine under test, and `--mode` says which half it carries.
`--peer` names a second Windows machine to run the client when the first is the server;
it defaults to `linux`, meaning this machine.

The rig checks every Windows end is set up for measurement, brings up the server and then
the client, waits for the tunnel to pass a ping, and runs `iperf3` from the client end.
Both directions share one control connection — forward is client to server, `-R` is
server to client — and they are reported separately because they are different paths in
the driver: encrypt-and-send through the transmit queue against receive-and-decrypt
through the socket.

Each direction runs several times and the median is reported, because a single run varies
more than any change worth noticing. A run that fails outright is retried once and then
left out rather than counted as zero.

`--seconds` is the length of a run, not of the measurement: the first few seconds are
dropped so TCP slow start does not drag a short run by a different amount each time.
Thirty seconds measures twenty-seven. Much below ten and the window left over swings by
half, which is enough to invent a regression or hide one, so the rig says how long it
actually measured and warns when that is short.

Each direction is also measured with one stream and with four, and both are worth the
time for different reasons. As a measurement the comparison is a diagnostic: the driver
has a single transmit queue and no RSS, so `-P 4` running far ahead of `-P 1` would mean
the single flow was limited somewhere other than the driver. As a workload, parallel
streams are a stressor — they have turned up driver bugs before — which is why CI keeps
both stream counts on every run and shortens the measurement instead when it needs to be
quicker.

## Requirements

Everything the stress rig needs, on every Windows machine involved, and in addition:

* a **release** build of the driver, test-signed like any other — the build signs itself,
  so this is `/p:Configuration=Release` and nothing more;
* Driver Verifier disarmed and the machine rebooted (`Set-TestMode.ps1 -Disarm`);
* `iperf3.exe`, since one end of the tunnel has to be there. `--iperf3` says where it is;
  the default is `C:\stage\iperf3.exe`.

Everything else a run needs — its own scripts, three of the stress rig's, and the right
half of the sample certificates — is copied across at startup.

The Linux side needs no packages beyond `openvpn` 2.7 and `iperf3`: the `ovpn` module is
in the kernel from 6.16, and OpenVPN uses it when it is there. The Linux scripts say
whether offload actually happened and fail if it did not, rather than quietly measuring a
userspace tunnel.

## The ceiling

AWS limits a single network flow to 5 Gbps inside a VPC, and a tunnel is exactly one
flow however many streams run inside it — so without care every test here measures that
limit rather than the driver. Inside a cluster placement group the limit doubles: a
single raw flow between these machines goes from 4965 to 9529 Mbit/s, and the tunnel
figures stop being suspiciously identical run to run.

All the rig's instances therefore live in one cluster placement group. That is an
attribute of each instance and survives stop and start, but nothing stops a replacement
being launched without it, and the only symptom would be every number dropping by about
a third — which reads exactly like a driver regression. CI prints each instance's group
and warns when they differ.

## Reading the result

A run ends in one line of JSON, and leaves the raw `iperf3` output and each Windows
end's driver counters under `--outdir`. `--markdown` appends a row per stream count to
a file, which is how CI collects every test into one table.

A run fails if a measurement cannot be trusted — no throughput at all, or an adapter
resetting while measuring, which drags an average down with no other sign that anything
happened — or if any median falls below `--min-mbit`, 1500 by default.

That floor is not a performance target. Throughput here varies by a factor of two
between runs on idle machines, so a tight bound would flap and then be ignored. The
lowest median measured across all the tests is about 2100 Mbit/s; the floor sits well
under it, so it catches a collapse and nothing else. Every median has to clear it, so a
failure in one direction or at one stream count is not hidden by the others, and the
row that failed is marked in the table.

## In CI

`.github/workflows/perf.yml` runs the rig on demand and on pull requests against
`multipeer`, and puts the table in the job summary. It shares the stress rig's machines
and its concurrency group, so the two never run at once: one wants a release driver with
Driver Verifier off and the other a checked build with it armed.

`perf-win-win-udp` needs a second Windows machine, named by the `PERF_PEER_INSTANCE_ID`
repository variable. Without it the test is skipped rather than failed. A dispatch can
turn it off with the `win_win` input when the extra machine is not worth the minutes.

`perf-linux-linux-udp` likewise needs a second Linux machine, named by
`PERF_LINUX_PEER_INSTANCE_ID`, and is skipped without one. That machine needs `iperf3`,
`openvpn` 2.7 and a kernel with the `ovpn` module, and it has to accept the load
generator's key — the rig reaches it the same way it reaches the Windows machines, with
`~/.ssh/dut_key`, so append that key's public half to its `authorized_keys` once.
