# ovpn-dco-win stress rig

A stress test for the driver as a multipeer server: many clients connecting,
disconnecting and passing traffic at once, with epoch keys rotating throughout.

Two machines. The Windows machine runs the driver under test and the OpenVPN server. A
Linux machine runs the clients and drives the run over SSH. The rig is PowerShell and
shell scripts; the only binary involved is the driver you are testing.

## What it does

Three workloads run together.

**Pairs** (`--pairs`, default 4) stay connected and send `iperf3` traffic to each other.
With `client-to-client` that traffic never leaves the kernel: the driver decrypts from one
client, the Windows network stack routes it back down to the same adapter, and the driver
looks the other client up in its peer table and encrypts it again.

**Swarm** (`--swarm`, default 16) clients connect, ping-flood the server, get killed while
those pings are in flight, and reconnect. Being killed mid-flight is the point: the driver
frees the peer and detaches its timer while packets for it are still being handled. Each
costs a namespace and a veth pair.

**Flood** (`--flood`, default 800) clients have no tunnel interface — `dev null`, no
address, no routes. They handshake, become a peer, idle briefly and exit, a wave at a
time. One process each, which is how a run reaches twenty thousand peer sessions.

So the swarm and the flood add and remove peers continuously while the pairs read the
peer table.

Three probes cover the route trie, which needs a word of explanation first.

The driver has two ways to find a peer. A peer's own tunnel address is in the **peer
table**. Subnets reachable *behind* a peer — iroutes — are in a **trie**, and the trie is
only consulted when the peer table misses. Nothing in an ordinary run reaches it: the
traffic pairs address each other's tunnel addresses, so the peer table answers every
time. Meanwhile peer churn inserts and removes trie entries thousands of times a run. So
the structure is being rewritten constantly and almost never read, which is the worst
combination to leave untested.

To reach it, every client is given the same iroute — `10.90.0.0/24` — in `ccd/DEFAULT`.
They share one certificate, so the server cannot tell them apart and cannot give them
different routes. Whichever peer connected last owns the prefix, and ownership moves
every time anyone connects.

**Probe 1, a destination behind a peer.** Each traffic client is given `10.90.0.5` on its
tun device: an address inside the subnet, and nobody's own tunnel address. The server
pings it. The peer table misses, the trie resolves the prefix to its owner, and the
packet is encrypted to that peer — which holds the address, so it answers. A reply means
the driver used the trie to route *out*. It does not say which peer answered: the reply
carries no such thing, and the next probe names the owner anyway.

**Probe 2, a source behind a peer.** A client pings the server's tunnel address, sourced
from `10.90.0.5` rather than its own. On receive the driver checks the source against the
sending peer, misses, and falls back to the trie. If the prefix belongs to that peer the
packet is accepted; if it belongs to another, it is dropped — a peer claiming a source it
does not own. So only the owner gets a reply, and the rig tries each client in turn: the
one that succeeds is the owner. A reply means the driver used the trie to validate a
source coming *in*.

Both run at startup, before the swarm and the flood begin, and that ordering matters.
Later in a run the owner is usually a `dev null` flood client with no interface at all,
which would resolve and deliver correctly and still never answer — a pass these probes
could not see.

**Probe 3, the load.** For the rest of the run every traffic client pings `10.90.0.9`, a
hundred packets a second each. That address belongs to nobody, which is the point: the
peer table can never answer it, so every packet reaches the trie. Each one crosses the
driver twice — up from the client, out through the server's host stack, and back down to
be looked up and sent to whoever owns the prefix, which by then is usually a flood client
that drops it. Nothing replies. The lookup is the point, not the round trip.

Two things that path depends on: the adapter must forward, the same requirement
client-to-client traffic has, and each client needs `10.90.0.0/24` added to its routing
table by hand — OpenVPN strips a pushed route from any client owning the matching iroute,
and here every client owns it.

Epoch keys rotate throughout. `TestAeadUsageLimit`, a registry value only checked builds
read, lowers the AEAD usage limit so keys rotate about every ninety thousand packets —
some 125MB at this MTU — instead of roughly every terabyte. The driver rotates its send
key, the client follows, and the driver then rotates its receive key, so both directions
rotate with unmodified clients.

The value is a compromise. A receiver follows a rotating sender by deriving a bounded
number of future keys — four in the driver, 16 in an OpenVPN client — and one that falls
further behind than that can never catch up, because it only advances its epoch on a
packet it could decrypt. It stays deaf until the session renegotiates.

The machines, the Actions variables and the AWS side are described in [../INFRASTRUCTURE.md](../INFRASTRUCTURE.md).

## Requirements

**Windows machine**

* A checked (Debug) build of the driver. `TestAeadUsageLimit` is read only under `DBG`.
* An ovpn-dco adapter that already exists. `pnputil` updates the driver on a device that
  is there but will not create one.
* Test signing on, and the signing certificate trusted in `LocalMachine\Root` and
  `LocalMachine\TrustedPublisher`.
* OpenSSH server, with the Linux machine's key in
  `%ProgramData%\ssh\administrators_authorized_keys`, not the user profile.
* Enough memory for Driver Verifier's special pool: when non-paged pool runs short it
  quietly stops using it and the checking stops happening. Static memory, not Hyper-V
  dynamic memory.
* OpenVPN 2.7 or later, built with the two changes below.
* IPv4 forwarding on the ovpn-dco adapter, which a fresh Windows install does not have.
  Without it every client reaches the server but no client reaches another, which looks
  like a broken peer table. `Start-Server.ps1 -Up` turns it on and `-Down` puts it back.

The server needs [1835](https://gerrit.openvpn.net/c/openvpn/+/1835), which restarts one
client instance instead of ending the process when a DCO key install fails, and
[1920](https://gerrit.openvpn.net/c/openvpn/+/1920), without which the Windows code never
reaches it. Without both, the server exits outright when the driver expires a peer just
before userspace installs its key. That binary is a prerequisite of the machine and
nothing here builds it; CI expects it at `C:\stage\ovpn-patched\openvpn.exe` and
`Start-Server.ps1` fails immediately if it is missing.

**Linux machine**

* `openvpn` 2.7 or later, `iperf3`, `tcpdump`, `iproute2`, `iptables`, `sudo`.
* Permission to create network namespaces.

Clients run with `disable-dco`, keeping their data channel in userspace: a client on
kernel DCO does not offer epoch data keys, so nothing would rotate. Distribution packages
are usually too old — Ubuntu 24.04 ships 2.6.19, and a 2.6 client never negotiates epoch
data keys — so use the community repository:

```sh
curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg |
    sudo gpg --dearmor -o /etc/apt/keyrings/openvpn.gpg
echo "deb [signed-by=/etc/apt/keyrings/openvpn.gpg] \
https://build.openvpn.net/debian/openvpn/release/2.7 $(lsb_release -cs) main" |
    sudo tee /etc/apt/sources.list.d/openvpn-27.list
sudo apt-get update && sudo apt-get install -y openvpn
```

Every client takes an address from the same server pool, so each runs in its own network
namespace, wired to the uplink through a veth pair and NAT.

## Keys

The sample certificates shipped with OpenVPN, in
`/usr/share/doc/openvpn/examples/sample-keys`; `run-stress.sh` copies the server's half
across, and `--keys` points elsewhere. Their private keys are published in the OpenVPN
source tree, which suits a throwaway rig on a private network and nothing else.

## Running

From the Linux machine:

```sh
tests/stress/run-stress.sh --dut <ssh-target> [--server-ip <dut-ip>] \
    [--pairs 4] [--swarm 16] [--flood 800] [--duration 600] [--outdir <dir>] \
    [--openvpn <path on the Windows machine>]
```

`--dut` says how to reach the Windows machine over SSH and can be an `ssh_config` alias.
`--server-ip` is the address clients dial; it defaults to `--dut` when that is a plain
address. The defaults are the configuration the rig was validated at — smaller numbers are
for debugging the rig, not for testing the driver.

The script sets `TestAeadUsageLimit`, turns on Driver Verifier, reboots the Windows
machine, starts the server, builds the client namespaces, runs the workload, collects logs
and counters, and prints a summary and a verdict under `--outdir`.

## Pass criteria

Every run ends with `PASS`, or `FAIL` and the reason, as one line of JSON. A failure also
prints the end of the server log and one client log.

The driver failed if the Windows machine stops answering SSH during the run (a bugcheck,
and the reason the rig runs from the Linux machine), if it stops answering while the
driver unloads at the end (Driver Verifier reports pool tracking only at unload, so a leak
bugchecks there), if `LostInData` reaches 1% of packets received, or if decryption fails
on 5% of them.

OpenVPN failed if the server process exited, which drops every client with it.

The run proved nothing, and must not pass, if no peer connected, if no swarm client did,
if a traffic pair could not reach its partner, if no epoch rotation was observed, if fewer
than 10000 data packets crossed the adapter, or if the adapter reset for more than a third
of the run. Count rotations rather than key derivations: a key is derived six times per
peer session before any traffic moves, so with a flood of short-lived peers the derivation
count is large whether or not anything rotated.

Everything else is reported and does not decide the verdict: throughput, the server's
per-client errors, the churn count, and losses under those thresholds.

**Throughput is never a pass or a fail.** It varies by a factor of two between runs on an
idle machine, and the Linux machine is usually the limit. Server Mbit/s comes from the
adapter every five seconds into `throughput.csv`; the two directions are never added,
because relayed traffic crosses the adapter twice. Client iperf3 Mbit/s covers the traffic
pairs only, and is mainly useful for spotting a pair that has stopped moving.

**A NIC reset is reported and tolerated.** On EC2 the adapter is ENA, whose driver resets
the device when its watchdog finds packets stuck in a transmit queue. While it is down
nothing moves and every client times out, so a run reads like a driver stall for about
ninety seconds. Windows names it with timestamps, so the run says so and carries on; the
events are in `nic-resets.txt`. A run fails once the outage passes a third of its
duration, and CI retries such a run up to three times. Any other failure stands the first
time.

## What the summary numbers mean

* **Peer counts** come from the server log (`MULTI: Learn`), not the client logs: OpenVPN
  truncates its log on every start.
* **The progress line** counts the swarm and the flood separately. `sw conn` and `sw t/o`
  are the swarm reconnecting, a few hundred over a run; `flood` is flood clients that
  completed a handshake, which reaches tens of thousands and is where the churn comes
  from.
* **Connect timeouts** in the swarm come from the rig, not the driver: the server
  handshakes one client at a time, so a swarm arriving at once overruns the client-side
  timeout well before the machine is loaded. That also caps useful load — past a few dozen
  swarm clients none finishes a handshake. On 16 vCPU the driver sat at about 10% CPU with
  12 swarm clients and with 48, so packet rate loads it, not peer count.
* **Decrypt failures** split three ways and the parts add up. `unknown epoch` is a packet
  the receiver has no key for, `late` when the epoch is already retired and `ahead` when it
  is past the four future keys. `auth failed` is a packet a key was found for whose tag did
  not verify, and it dominates: peer ids are reused, so traffic still arriving for the
  previous occupant lands on a receive context that has started again. `replay` is a packet
  id already seen.
* **`LostOutData`** counts packets queued for a peer torn down under them; **`LostInData`**
  counts packets that arrived for a peer already gone, or found no free buffer. Both are
  normal while the swarm kills clients mid-flight, and only `LostInData` fails a run.
* **Errors and churn** split what the server complains about. Churn is the noise the swarm
  makes by design: abandoned handshakes, and source ports the kernel hands to a new client
  while the server still has a session on that address. Neither decides the verdict, and
  the driver's own replay rejects are in neither — they are `LostInData`.

## Known limitation: control is in-band

The signal that something went wrong is the Windows machine no longer answering SSH, and
that answer travels over the machine that just died. A run can say the driver died, never
why: there is no stop code and no crash dump. If SSH shares an interface with the tunnel
traffic, heavy load can starve it and look the same as a bugcheck; `run-stress.sh` warns
at startup when the control address and `--server-ip` are the same.
