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
| device under test | Windows | stress, `perf-client-*`, `perf-server-udp`, `perf-win-win-udp` |
| load generator | Linux | every run — it drives the rigs and is one tunnel end |
| second Windows machine | Windows | `perf-win-win-udp` only |
| second Linux machine | Linux | `perf-linux-linux-udp` only |

Each is named by an Actions variable: `STRESS_DUT_INSTANCE_ID`,
`STRESS_CLIENT_INSTANCE_ID`, `PERF_PEER_INSTANCE_ID` and `PERF_LINUX_PEER_INSTANCE_ID`.
The last two are optional — the tests that need them are skipped when they are unset,
rather than failing.

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
