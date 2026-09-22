# ovpn-dco-win ioctl rig

Drives the driver's ioctl surface directly, rather than through OpenVPN.

The stress rig reaches the driver the way OpenVPN does, so it only ever produces orderings
OpenVPN produces, at the rate a TLS handshake allows. This one talks to the device itself:
malformed buffers, values outside what the structs are meant to carry, control codes that
do not exist, and — later — peer churn at memory speed rather than handshake speed.

It needs one Windows machine, no Linux, no network and no certificates, so a run is
seconds rather than minutes.

## What it does today

| mode | what it sends |
| --- | --- |
| `--mode mutate` | every ioctl, in multipeer mode, with mutated buffers |
| `--mode mutate-p2p` | the same in point-to-point mode, which should refuse the multipeer half |
| `--mode unknown` | control codes the driver does not implement |
| `--mode churn` | six threads on the one handle, with datagrams arriving throughout |

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

`churn` is the concurrency half. Six threads share the single handle: one creating and
deleting peers across a deliberately small id space so ids are reused constantly, one
installing and swapping keys on ids another thread is deleting, one moving iroutes
between peers on overlapping prefixes, one reading stats, one parked on `NOTIFY_EVENT`
the way a userspace server is, and one firing data-channel datagrams at the driver's own
listen port, and one sending packets the other way, into the tunnel.

Those datagrams carry a real opcode and peer id and a garbage payload, so they never
decrypt. That is the point: they still drive the receive path, the peer lookup and the
loss counters while peers are being freed underneath, which is the shape of the
peer-table use after free, and they cost nothing — no handshake, no crypto, no far end.

Five minutes produces around 1.2M peer lifecycles and 7M packets, against the stress
rig's twenty thousand peer sessions in ten. That ratio is the reason this rig exists.

## Running

The device is exclusive — `WdfDeviceInitSetExclusive` in `Driver.cpp` — so the harness
owns it for the run and cannot share it with OpenVPN. Stop OpenVPN first.

```
ovpn-ioctl-test.exe [--mode mutate|mutate-p2p|unknown|churn] [--seed N]
                    [--seconds N] [--port N]
```

Every run prints its seed and takes `--seed` to repeat one exactly.

Each call goes out overlapped with a two second deadline. `NOTIFY_EVENT` parks by design
until an event arrives, and a call that parks is cancelled and counted rather than waited
on — so the sweep finishes, and an ioctl that parks when it should not is visible instead
of being a hang. Cancelling a parked request also exercises the driver's cancel path.

The count is kept per control code, and anything other than `NOTIFY_EVENT` is called out,
because the two mean opposite things: that one parking is the design, and any other ioctl
taking two seconds is worth looking at.

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
than failed when that is unset. It still shares the hardware concurrency group, because
the perf rig's windows-to-windows test uses that same machine.

A run installs a checked build, arms Verifier, reboots, drives all four modes, then
unloads the driver so pool tracking reports. The machine failing to answer after that
unload is the finding, not the harness's own output.

Build the harness by path, not through the solution — it is a user-mode tool and has no
business in the driver's build matrix:

```
msbuild /p:Configuration=Release /p:Platform=x64 tests\ioctl\ovpn-ioctl-test.vcxproj
```

## Not yet

The inbound and outbound halves reach different code. Inbound drives the receive path
and the peer lookup; outbound gives the adapter an address and aims packets at both a
peer's VPN address and the iroute range, so the transmit path resolves each through
`OvpnFindPeerVPN4` and then the route trie while another thread moves those prefixes
between peers. That trie lookup on the datapath has had a use after free before.

* **Valid traffic.** The datagrams never decrypt, so a peer is never torn down while it
  holds live crypto state and a real packet is mid-flight. Implementing the data channel
  here would close that, and it is the largest remaining gap.
* **Handle close races.** `OvpnEvtFileCleanup` tears down device state; closing the
  handle while other threads are mid-ioctl is untested.
* **The P2P personality under churn.** Only the multipeer half is exercised concurrently.
This is randomised input and ordering testing, not coverage-guided fuzzing. There is no
feedback loop telling it which inputs reached new code.
