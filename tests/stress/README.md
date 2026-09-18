# ovpn-dco-win stress rig

A stress test for the driver running as a multipeer server: many clients connecting,
disconnecting and passing traffic at the same time, with epoch keys rotating throughout.

Two machines are involved. The Windows machine runs the driver under test and the OpenVPN
server. A Linux machine runs the clients and drives the whole run over SSH. The rig is
PowerShell and shell scripts; the only binary involved is the driver you are testing.

## What it does

Three workloads, which can run at the same time.

**Pairs** (`--pairs`, default 4) are clients that stay connected for the whole run and
send `iperf3` traffic to each other. The server has `client-to-client` on, so that
traffic never leaves the kernel: the driver decrypts a packet from one client and hands
it to the Windows network stack, which routes it straight back down to the same adapter,
where the driver looks the other client up in its peer table and encrypts it again.
OpenVPN never sees these packets. `--pairs 4` means four pairs, so eight clients.

**Swarm** (`--swarm`, default 16) clients run in a loop for the whole run: connect, flood
the server with pings for a second and a half, get killed while those pings are still in
flight, reconnect, repeat. Being killed mid-flight is the point, because the driver then
has to free the peer and detach its timer while packets for it are still being handled.
Each swarm client needs its own network namespace and veth pair, which is what limits how
many of them you can run.

**Flood** (`--flood`, default 800) clients have no tunnel interface at all: `dev null`,
no address, no routes. They complete a handshake, become a peer on the server, sit idle
for five seconds and exit. The whole batch runs as a wave, and a new wave starts when
the last one finishes. They carry no data whatsoever, and cost one process each instead
of a namespace, which is the cheap way to reach the peer counts of a real outage
recovery.

Together, the swarm and the flood keep adding and removing peers while the pairs read the
peer table. The single-peer tests never reach that.

Two one-packet probes run at startup, before the churn begins. One pings the iroute
subnet from the server and watches every peer to see which one receives it, which
exercises the route trie lookup on the way out. The other gives that peer an address
inside the subnet and pings back from it, which exercises the reverse path filter the
driver applies to every packet it decrypts: a source that is not a peer own address is
looked up in the trie and must resolve to the peer that sent it. Both are reported and
neither fails a run.

Epoch keys rotate the whole time. A registry value that only checked builds read,
`TestAeadUsageLimit`, lowers the AEAD usage limit so keys rotate every few thousand
packets instead of roughly every terabyte. The driver rotates its send key, the client
follows it, and the driver then rotates its receive key, so both directions rotate
continuously with unmodified clients.

The value is a compromise rather than "as fast as possible". A receiver follows a
rotating sender by deriving a bounded number of future keys -- four in the driver, 16 in
an OpenVPN client -- and a receiver that misses more rotations than that can never catch
up, because it only advances its epoch on a packet it could decrypt. It stays deaf until
the session is renegotiated.

Rotating every few hundred packets, as this rig first did, left a receiver about a tenth
of a second of loss before that happened, and the traffic pairs lost their data channel
and reconnected every few minutes. Raising the limit to two million fixed the pairs but
a run still ended with 2206 receivers past the window, against 327 rotations. The
default is four times higher again: about 80 rotations in a fifteen-minute run, which
still exercises both rotation paths many times over, and minutes of slack instead of
seconds. The summary reports the split, so a run says which way it went.

## Requirements

**Windows machine**

* A checked (Debug) build of the driver. `TestAeadUsageLimit` is read only under `DBG`.
* An ovpn-dco adapter that already exists. `pnputil` updates the driver on a device that
  is there, but it will not create one, so install OpenVPN with the DCO adapter once
  first.
* Test signing on, and the certificate that signed the driver trusted in
  `LocalMachine\Root` and `LocalMachine\TrustedPublisher`.
* OpenSSH server, with the Linux machine's key authorised. Administrator keys go in
  `%ProgramData%\ssh\administrators_authorized_keys`, not in the user profile.
* Enough memory for Driver Verifier's special pool. When non-paged pool runs short it
  quietly stops using special pool, and the checking it was there to do stops happening.
  Give the machine static memory rather than Hyper-V dynamic memory, which shrinks the
  guest while the host still reports the full size.
* OpenVPN 2.7 or later. Epoch data keys are only negotiated from 2.7 on. For now this
  has to be a custom build; see below.
* IPv4 forwarding on the ovpn-dco adapter. A fresh Windows install does not have it, and
  without it every client can reach the server but no client can reach another, which
  looks like a broken peer table. `Start-Server.ps1 -Up` turns it on and `-Down` puts it
  back, so there is nothing to do by hand.

The OpenVPN server needs two changes that are not merged yet, both open on Gerrit:

* [1835](https://gerrit.openvpn.net/c/openvpn/+/1835), "dco: do not exit the process
  when installing a DCO key fails", which restarts the one client instance instead;
* [1920](https://gerrit.openvpn.net/c/openvpn/+/1920), "dco_win: report per-peer ioctl
  failures instead of exiting", without which the Windows code never reaches 1835: it
  reports the failed ioctl with M_ERR, so the process is gone before the error returns.

Without them the server exits outright when the driver expires a peer microseconds
before userspace installs its key, which at these defaults happens in roughly one run in
three. The run then fails, correctly, as an OpenVPN fault rather than a driver one, but
it tests nothing past that point. Build openvpn with both, put it on the Windows
machine, and pass `--openvpn <path>` to `run-stress.sh`.

That binary is a prerequisite of the machine, like the adapter and the trusted test
certificate, and nothing in this repository builds it. CI expects it at
`C:\stage\ovpn-patched\openvpn.exe`, which is the default of the workflow's `openvpn`
input. `Start-Server.ps1` fails immediately if it is not there rather than running the
stock server and failing twenty minutes later.

**Linux machine**

* `openvpn` 2.7 or later, `iperf3`, `iproute2`, `iptables`, `sudo`.
* Permission to create network namespaces.

The clients run with `disable-dco`, which keeps their data channel in userspace. A client
using kernel DCO does not offer epoch data keys, so the server never negotiates them and
nothing rotates. A run in which no rotation was observed fails, rather than passing while
testing nothing.

Distribution packages are usually too old for this. Ubuntu 24.04 ships 2.6.19, and a 2.6
client never negotiates epoch data keys at all. Use the community repository:

```sh
curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg |
    sudo gpg --dearmor -o /etc/apt/keyrings/openvpn.gpg
echo "deb [signed-by=/etc/apt/keyrings/openvpn.gpg] \
https://build.openvpn.net/debian/openvpn/release/2.7 $(lsb_release -cs) main" |
    sudo tee /etc/apt/sources.list.d/openvpn-27.list
sudo apt-get update && sudo apt-get install -y openvpn
```

Every client gets an address from the same server pool, so they cannot share one routing
table. Each one runs in its own network namespace, connected to the uplink through a veth
pair and NAT.

## Keys

The rig uses the sample certificates that come with the OpenVPN package on the Linux
machine, in `/usr/share/doc/openvpn/examples/sample-keys`, and `run-stress.sh` copies the
server's half across. Use `--keys` if your distribution keeps them somewhere else.

Their private keys are published in the OpenVPN source tree. That is fine for a throwaway
rig on a private network and for nothing else.

## Running

From the Linux machine:

```sh
tests/stress/run-stress.sh --dut <ssh-target> [--server-ip <dut-ip>] \
    [--pairs 4] [--swarm 16] [--flood 800] [--duration 900] [--outdir <dir>] \
    [--openvpn <path on the Windows machine>]
```

The defaults are the configuration the rig was validated at, and the one that has found
bugs: 27000 peer sessions in a five-minute run, enough peer expiries to hit races that a
quieter run never reaches. Smaller numbers are for debugging the rig itself, not for
testing the driver.

`--dut` says how to reach the Windows machine over SSH. It can be an `ssh_config` alias,
so it is not always an address.

`--server-ip` is the address the clients dial to reach the OpenVPN server. If `--dut` is
already a plain address, that is used and you can leave this out. Otherwise it is
required. The two differ when SSH and the tunnel do not take the same route: an SSH
alias, a separate management NIC, or a public address in front of a private one.

The script sets `TestAeadUsageLimit`, turns on Driver Verifier, reboots the Windows
machine, starts the server, builds the client namespaces, runs the workload, samples
epoch rotations, collects the logs and counters, and prints a summary and a verdict.

Everything lands under `--outdir`, `./stress-results/<timestamp>` by default: the run
transcript, the server log, a log per client, and the driver's counters from before and
after.

## Pass criteria

Every run ends with `PASS`, or `FAIL` and the reason, as one line of JSON. A failure also
prints the end of the server log and one client log.

The driver failed if:

* the Windows machine stops answering SSH during the run. That means a bugcheck. It is
  the main thing the rig watches for, and the reason it runs from the Linux machine
  instead of on the machine being tested;
* the Windows machine stops answering while the driver unloads at the end. Driver
  Verifier only reports its pool tracking at unload, so anything the driver leaked
  bugchecks there;
* `LostInData` reaches 1% of the packets received. More peers are going away under
  traffic than the churn accounts for;
* decryption fails on 5% of the packets received. Rotation is losing packets, not just
  running ahead of the four future keys a receiver keeps.

OpenVPN failed if:

* the server process exited, which drops every client with it. A key installed for a peer
  the driver had just expired used to end the process this way.

The run itself was no good, and must not be called a pass, if:

* no peer connected, or no swarm client did (use a smaller `--swarm`);
* one of the traffic pairs could not reach its partner;
* no epoch rotation was observed, so the run used ordinary data keys and never tested
  rotation. Count rotations, not key derivations: a key is derived six times per peer
  session before any traffic moves, so with a flood of short-lived peers the derivation
  count is large whether or not anything rotated;
* fewer than 10000 data packets crossed the adapter;
* the Windows machine reset its network adapter more than twice (see below).

Everything else is reported but does not decide the verdict: throughput, the server's
per-client errors, the churn count, and lost or undecryptable packets under the
thresholds above. A multipeer server with this much churn logs per-client errors all the
time, including a key refused for a peer that has just expired.

A **NIC reset on the Windows machine** is reported but does not by itself fail a run. On
EC2 the adapter is ENA, whose driver resets the device when its watchdog finds no
keep-alive or packets stuck in a transmit queue. While it is down nothing moves, every
client times out and reconnects, and the sampler blocks, so a run reads like a driver
stall for about a minute. It is not one, and Windows names it with timestamps, so the
run says so and carries on: the gap is visible in the throughput samples and the events
are in `nic-resets.txt`. Past two resets the run fails instead, because by then too
little of it ran with a working adapter to judge.

Throughput in particular is never a pass or a fail. It varies by a factor of two between
runs on an idle machine, and the Linux machine is usually the limit, not the driver.

Two throughput numbers are reported, measured in different places.

*Server* Mbit/s is read from the ovpn-dco adapter on the Windows machine every five
seconds, into `throughput.csv` along with CPU. It covers everything the driver carried,
the swarm's floods as well as the pairs. The two directions are listed separately and
never added up: relayed traffic crosses the adapter twice, once up to the Windows network
stack and once back down, so a total would count it twice.

*Client* iperf3 Mbit/s is the average across the traffic pairs and nothing else. The
Linux machine's own encryption usually limits it before the driver does. It is mainly
useful for noticing a pair that has stopped moving.

Each sample is written as it is taken, so a run that ends in a bugcheck still has
everything up to the moment the machine went quiet.

## What the summary numbers mean

* **Peer counts** come from the server log (`MULTI: Learn`). Do not count them from the
  client logs. OpenVPN truncates its log every time it starts, so a client log only shows
  that client's most recent connection.
* **Connect timeouts** in the swarm come from the rig, not the driver. An OpenVPN server
  does handshakes one at a time, so a swarm that arrives all at once will run past the
  client's timeout long before the machine is under any real load. They only matter if
  the server is logging errors as well.
* Handshakes being serial also limits how much load is worth asking for. Past a few dozen
  swarm clients, none of them finishes a handshake, the churn stops happening, and
  throughput drops instead of rising. That is why a run with no swarm connects fails. On
  16 vCPU the driver sat at about 10% CPU with 12 swarm clients and with 48, so what
  loads it is the packet rate, not the number of peers.
* **`LostOutData`** counts packets that were queued for a peer which was then torn down.
  **`LostInData`** counts packets that arrived for a peer that was already gone, or that
  found no free buffer. Both are normal while the swarm kills clients mid-flight. Only
  `LostInData` can fail a run, and only past the 1% above. Decryption failures are counted
  on their own and fail a run past 5%, because showing that constant rotation does not
  break decryption is what the run is for.
* The summary splits what the server complains about into **errors** and **churn**.
  Churn here is a category of log line, not one of the workloads above. It is the noise
  the swarm makes on purpose: handshakes abandoned when a client is killed, and source
  ports the kernel hands to a new client while the server still has a session on that
  address. That shows up as a refused float, a TLS record that will not verify, or a
  replay warning from OpenVPN's own window. Neither count decides the verdict. The
  driver's replay rejects are in neither of them; they are `LostInData`.

## Known limitation: control is in-band

The signal that something went wrong is the Windows machine no longer answering SSH. That
answer travels over the machine that just died, so by the time the rig notices, it has
already lost any way to ask what happened. A run can say that the driver died, never why.
There is no stop code and no crash dump.

There is a second problem if SSH shares an interface with the tunnel traffic: heavy load
can starve the SSH connection, and that looks the same as a bugcheck. `run-stress.sh`
warns at startup when the control address and `--server-ip` are the same. A machine with
its own management interface does not have that ambiguity.
