# What the rigs run on

The stress and perf rigs run against real machines rather than a VM, and that machinery
lives in three places: this repository, the repository's Actions settings, and AWS. Only
the first is reviewable in a pull request, which is why this file exists.

No identifiers here. Account numbers, instance ids, security group and subnet ids, image
ids and addresses all live in Actions variables, where a public repository cannot leak
them. This file describes the shape, and names the variables that hold the values.

## The machines

| role | system | used by |
| --- | --- | --- |
| device under test | Windows | `perf-client-*`, `perf-server-udp`, `perf-win-win-udp` |
| load generator | Linux | perf — it drives the rig and is one tunnel end |
| stress pair | Windows + Linux | stress, the same two roles on machines of its own |
| second Windows machine | Windows | `perf-win-win-udp` only |
| second Linux machine | Linux | `perf-linux-linux-udp` only, and only on a dispatch |
| ioctl target | Windows | ioctl |

Each is named by an Actions variable: `STRESS_DUT_INSTANCE_ID`,
`STRESS_CLIENT_INSTANCE_ID`, `PERF_PEER_INSTANCE_ID`, `PERF_LINUX_PEER_INSTANCE_ID`,
`IOCTL_TARGET_INSTANCE_ID`, `PERF_DUT_INSTANCE_ID` and `PERF_CLIENT_INSTANCE_ID`.

Only the first two are required. The peers are optional and the tests that need them
are skipped when they are unset. The last three name the machines that ended the
queueing: without `IOCTL_TARGET_INSTANCE_ID` the ioctl rig borrows the second Windows
machine, and without the `PERF_*` pair perf measures on the stress pair. Each rig falls
back to sharing, and to waiting, exactly as it did before.

Perf keeps the original machines and stress moved to the clones, not the other way
round: perf's numbers are comparable across weeks only because the hardware under them
never changes.

They are kept stopped and started per run, because a run owns them for tens of minutes
and nothing else should be using them.

## Where configuration lives

**In this repository:** the rigs under `tests/`, the two workflows, and the per-machine
prerequisites in each rig's README.

**In Actions variables:** `AWS_REGION`, `STRESS_SECURITY_GROUP` and the four instance
variables above.

**In Actions secrets:** `STRESS_AWS_ROLE_ARN`, the role a run assumes over OIDC, and
`STRESS_SSH_KEY`, the private key for the machines. There are no long-lived AWS keys.

**In AWS, and nowhere else:**

* an IAM role with an OIDC trust for this repository, and a policy described below;
* one security group holding all the machines;
* a **cluster placement group** holding all of them, for the reason in `perf/README.md`:
  a tunnel is a single network flow, and outside such a group a single flow is capped
  near 5 Gbps, which is close enough to what the driver achieves to hide the difference;
* the machines themselves, including hand-made state — a test-signed driver, a trusted
  signing certificate, an existing DCO adapter, `iperf3`, an OpenVPN build, and the
  authorised keys that let the load generator reach the others.

## What the role may do

Scoped deliberately narrowly, because a run authorises its own address into a security
group:

| action | scope |
| --- | --- |
| `ec2:DescribeInstances` | everything — it is read-only |
| `ec2:StartInstances`, `ec2:StopInstances` | **each rig instance, named by ARN** |
| `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress` | the one security group |

A run opens SSH from the runner's own address for the duration and revokes it afterwards,
so nothing is reachable from the internet between runs.

## Sharing the machines

Which rig needs what:

| rig | machines | driver it installs |
| --- | --- | --- |
| stress | its own Windows and Linux pair | checked, Verifier armed |
| perf | device under test, load generator, both peers | release, Verifier off |
| ioctl | its own Windows machine | checked, Verifier armed |

No rig waits for another any more. Each still waits for *itself*: one machine each
means two pull requests cannot run the same rig at once, and the concurrency group
only supersedes runs on the same branch - it does nothing across branches. Skipping
that wait let a second run stop the machine under the first, which reads as a rig
that cannot reach its own device. What the sharing cost is worth stating,
because the fallbacks still describe it: sharing a device under test means stress and
perf can never run together - same machines, opposite driver states - and stress waited
out perf's whole measurement, twenty-six minutes for a seven-minute workload. The ioctl
rig shares nothing with either, yet waited twenty-five minutes for a ten-minute run,
because the windows-to-windows test borrows the machine it drives.

Each workflow does keep a group of its own, `workflow + branch`, purely to supersede
its own older run when a new commit arrives — otherwise an obsolete run does not just
linger, it blocks the new one at the wait.

Per-run instances would end the remaining wait too: it exists only because a rig owns one
machine, so the second pull request queues behind the first.

A shared group across rigs looks like the answer for the machines and is not: GitHub keeps only
one *pending* run per group, so a third run cancels the one that was waiting rather than
queueing behind it. Each workflow therefore waits explicitly, and only for the rigs it
actually collides with. The wait is ordered by run id, which is total, so a run only ever
waits for older ones and the three cannot deadlock.

Dedicated machines only go so far: they are still one each, so two pull requests at once
queue exactly as two rigs used to.

The better answer is a machine per run, launched from an image and terminated after. The
image half now exists - `ovpn-dco-rig-windows`, a snapshot of the second Windows machine
taken while stopped, which is where the ioctl target came from. What is missing is
`RunInstances` scoped by tag and instance type rather than the current start/stop on
named ARNs, and something to reap instances a cancelled run left behind.

The image is deliberately not sysprepped. Generalising regenerates the SID and re-runs
specialize, which disturbs the one piece of state every rig assumes is already there: an
existing DCO adapter. These machines join no domain, so duplicate SIDs cost nothing.

## Adding a machine takes three changes

This is the part that has caught us out, so it is worth stating plainly. Adding a machine
to a rig needs all three of:

1. an Actions variable naming it;
2. the workflow starting, reaching and stopping it;
3. **its ARN added to the IAM policy's start/stop statement.**

Only the second is visible in a pull request. Missing the third fails at `StartInstances`
with `UnauthorizedOperation`, which cannot be reproduced locally because a developer runs
the rigs under their own credentials rather than the role.

## Rebuilding this

There is no infrastructure as code yet, and that is the largest gap here. The AWS side —
role, policy, security group, placement group — is small and entirely amenable to it. The
machines are harder, because they carry state built by hand: Windows test signing, a
trusted certificate, an existing adapter, a patched OpenVPN build. Those are documented as
prerequisites in each rig's README but nothing provisions them.
