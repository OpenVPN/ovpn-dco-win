# ovpn-dco-win ioctl rig

Drives the driver's ioctl surface directly, rather than through OpenVPN.

The stress rig reaches the driver the way OpenVPN does, so it only ever produces orderings
OpenVPN produces, at the rate a TLS handshake allows. This one talks to the device itself:
malformed buffers, values outside what the structs are meant to carry, control codes that
do not exist, and peer churn at memory speed rather than handshake speed.

It needs one Windows machine, no Linux, no network and no certificates. The sweeps take
seconds; a churn run lasts as long as you give it.

## What it does today

| mode | what it sends |
| --- | --- |
| `--mode mutate` | every ioctl, in multipeer mode, with mutated buffers |
| `--mode mutate-p2p` | the same in point-to-point mode, which should refuse the multipeer half |
| `--mode unknown` | control codes the driver does not implement |
| `--mode churn` | nine threads on the one handle, with datagrams arriving throughout |
| `--mode selfsend` | one deadlock, deliberately — see below, and not for CI |

Mutation covers three things. **Buffer shapes**: input truncated to one byte and to one
short of the struct, oversized, absent; output too small, absent. This is where two of the
driver's past findings were — a short input read past its end, and output padding going
back to userspace — so it runs against every ioctl. **Values**: peer ids at the ends of
the range, key lengths that are not 16, 24 or 32, cipher and slot enums past their last
member, prefix lengths past 32 and 128, and `sockaddr` families that decide how far the
driver reads. **Pointers**: null with a non-zero length, and lengths that would overflow a
size calculation.

Nothing asserts on the status a call returns. A refusal is the right answer to most of
this and the driver is free to choose which refusal, so the run reports what happened and
only calls out the cases that should not have been accepted at all: a buffer shorter than
the struct the driver reads, or a value outside its documented range.

`churn` is the concurrency half. Nine threads share the single handle: one creates and
deletes peers across a deliberately small id space, so ids are reused constantly; one
installs and swaps keys on the ids that thread is deleting; one moves iroutes between
peers on overlapping prefixes; one reads stats; one stays parked on `NOTIFY_EVENT` the
way a userspace server does; two work the control channel with `ReadFile` and
`WriteFile`; and two push packets — one at the driver's own listen port, one the other
way, into the tunnel.

The control channel is its own surface and nothing else here touches it. Writes are
where the mutations go: in MP mode the payload is prefixed with a `SOCKADDR` and the
driver switches on `sa_family` to decide how far to skip, so the thread sends a buffer
holding `sa_family` and nothing else, one exactly the length of the prefix so no payload
is left, an `AF_INET6` family over an `AF_INET`-sized buffer, families the switch does
not know, and payloads either side of the MTU cap. Reads are where the ordering goes:
`OvpnEvtIoRead` parks the request and then re-checks the queue under `ControlRxLock`,
while the receive side takes the same lock to either hand the packet to a parked reader
or queue it — the lost wakeup from #136. The traffic thread gives one packet in 256 a
control opcode so both sides run continuously, and rarely on purpose: a flood would
just leave a backlog, and a reader that never has to park never races anything.

Those datagrams carry a real opcode and peer id over a garbage payload, so they never
decrypt. That is the point: they still drive the receive path, the peer lookup and the
loss counters while peers are being freed underneath, which is the shape of the
peer-table use after free, and they cost nothing — no handshake, no crypto, no far end.

The two directions reach different code. Inbound drives the receive path and the peer
lookup. Outbound gives the adapter an address and aims at both a peer's VPN address and
the iroute range, so the transmit path resolves each through `OvpnFindPeerVPN4` and then
the route trie while another thread moves those prefixes between peers — and that trie
lookup on the datapath has had a use after free.

Half the keys are installed as epoch keys, and the datagrams carry a packet id whose
epoch lands on the current key, the retiring one, each of the future keys, the first
epoch past them, and the ends of the 16 bit range. The driver reads that epoch and looks
its key up *before* it verifies anything, so packets that will never decrypt still drive
the ratchet and the bounded future-key derivation — which is where the epoch future-keys
finding lived.

The top quarter of the id space belongs to the driver: those peers are created with a two
second keepalive timeout and never deleted by hand, so the driver's own timer expires
them while the other threads work. They are freed from `OvpnTimerRecv` rather than from
an ioctl, which is the path issue #141 was about.

A run reports how many epoch keys the driver took, how many peers it expired and how
many control packets reached a read. These
counters are there because what they catch is silent: the first expiry lane re-armed the
keepalive on every pass, and `MP_SET_PEER` restarts the receive timer, so nothing ever
expired — and the run looked exactly like a clean one.

Five minutes produces around 1.2M peer lifecycles and 7M packets, against the stress
rig's twenty thousand peer sessions in ten. That ratio is the reason this rig exists.

## Running

The device is exclusive — `WdfDeviceInitSetExclusive` in `Driver.cpp` — so the harness
owns it for the run and cannot share it with OpenVPN. Stop OpenVPN first.

```
ovpn-ioctl-test.exe [--mode mutate|mutate-p2p|unknown|churn|selfsend] [--seed N]
                    [--seconds N] [--port N] [--no-packets]
```

Every run prints its seed and takes `--seed` to replay it. That is exact for the sweeps.
For `churn` it replays the choices each thread makes, not the order the threads make
them in, so a seed narrows a crash down rather than pinning it.

Each call goes out overlapped with a two second deadline. `NOTIFY_EVENT` parks by design
until an event arrives, and a call that parks is cancelled and counted rather than waited
on — so the sweep finishes, and an ioctl that parks when it should not is visible instead
of being a hang. Cancelling a parked request also exercises the driver's cancel path.

## What the verdict is

The harness only reports what the driver returned. The verdict comes from the machine:

* it is still answering afterwards, so nothing bugchecked;
* Driver Verifier found nothing, which is where the real oracle is;
* the driver unloads cleanly at the end, since pool tracking only reports leaks there.

Run it with Verifier armed at `0x20029` — special pool, pool tracking, deadlock detection
and **DDI compliance checking**. That last one the stress rig deliberately leaves off, and
it is the one worth having here, because calling ioctls from several threads is where DDI
and IRQL misuse shows up.

Arm all three of `ovpn-dco.sys`, `netadaptercx.sys` and `ndis.sys` together. Verifying the
client without Cx makes NetAdapterCx report false NDIS rule violations, and it says so on
the debugger before it breaks.

## In CI

`.github/workflows/ioctl.yml` runs it on demand and on pull requests against `multipeer`.
It needs one Windows machine and no network peer, so it uses the second Windows machine
rather than the device under test — named by `PERF_PEER_INSTANCE_ID`, and skipped rather
than failed when that is unset. It waits for the perf rig rather than sharing a
concurrency group — a group cancels the waiting run instead of queueing it — because the
perf rig's windows-to-windows test borrows that same machine. `tests/INFRASTRUCTURE.md`
says which rig uses what.

A run installs a checked build, arms Verifier, reboots, drives all four modes, then
unloads the driver so pool tracking reports. The machine failing to answer after that
unload is the finding, not the harness's own output.

Build the harness by path, not through the solution — it is a user-mode tool and has no
business in the driver's build matrix:

```
msbuild /p:Configuration=Release /p:Platform=x64 tests\ioctl\ovpn-ioctl-test.vcxproj
```

## The deadlock this found

`OvpnEvtIoWrite` takes `device->SpinLock` **shared** and holds it across `OvpnSocketSend`
(`Driver.cpp:238` to `:345`). When the destination is one of the machine's own addresses
on the driver's own port, tcpip delivers the datagram inline, on the sending thread
(`IppLoopbackEnqueue`), so the driver re-enters its own receive path. If the packet is a
data packet, `OvpnSocketDataPacketReceived` looks the peer up and `OvpnFindPeer`
(`peer.cpp:332`) asks for that same lock shared again. A control packet does not: it goes
to `OvpnSocketControlPacketReceived`, which takes `ControlRxLock` and nothing else, and
re-enters harmlessly — 600k of them proved that before the repro was corrected.

That is prohibited outright: `ExAcquireSpinLockShared` documents that the caller must not
already own the lock, and that recursive acquisition causes deadlock. What decides whether
it deadlocks *today* is that `EX_SPIN_LOCK` prefers writers — with nobody waiting for the
lock exclusive the second acquire is indistinguishable from a second reader and succeeds
(measured: 3.78M of them in thirty seconds, untroubled), and with a writer waiting it
queues behind them, the writer waits for the first acquire to be released, and neither
moves again. That is implementation behaviour, not a guarantee; the contract is broken
either way.

The writer needs no help from userspace — in the captured stack it was the keepalive timer
expiring a peer, `OvpnTimerRecv` → `OvpnPeerDelete` → `OvpnDeletePeerFromTable`
(`peer.cpp:463`). Cores spin at DISPATCH and the machine does not come back. It does not
bugcheck under a kernel debugger, which disables the DPC watchdog; without one a spinning
DPC should reach `DPC_WATCHDOG_VIOLATION` instead.

`--mode selfsend` reproduces it on purpose: writes addressed to the driver's own listen
port carrying a `DATA_V2` payload, with a peer thread alongside to keep a writer queued.
It wedges an unfixed driver in about five seconds. It is not one of the modes CI runs,
because it costs a reset.

## Not yet

* **Valid traffic.** The datagrams never decrypt, so a peer is never torn down while it
  holds live crypto state and a real packet is mid-flight. Implementing the data channel
  here would close that, and it is the largest remaining gap.
* **TCP transport.** The length-prefix reassembly in `OvpnSocketTcpReceiveEvent` splits
  packets across indications and MDLs, and whatever is on the other end of the socket
  chooses how. TCP is P2P only and the driver connects out, so a loopback listener here
  could feed it directly. Nothing does yet.
* **Handle close races.** `OvpnEvtFileCleanup` tears down device state; closing the
  handle while other threads are mid-ioctl is untested.
* **The P2P personality under churn.** Only the multipeer half is exercised concurrently.

This is randomised input and ordering testing, not coverage-guided fuzzing. There is no
feedback loop telling it which inputs reached new code.
