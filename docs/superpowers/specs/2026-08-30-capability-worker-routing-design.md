# Capability-Aware Worker Routing Design

**Status:** Approved for implementation by the repository owner on 2026-08-30.

## Objective

Route queued work by server-derived execution requirements. Prevent the local
Compose worker and the enrolled Linux detonation agent from processing the
same job through different Redis consumer groups. Make incompatible workers
reject work before execution.

## Current failure

The Compose worker and enrolled agent read one Redis stream but use different
consumer-group names. If both run, Redis can deliver the same entry once to
each group. The agent also accepts operator-supplied capability labels without
checking a job's requirements. Risky analysis is forced to Lima even though the
Linux installer and beta health contract require KVM, libvirt, and `virsh`.

## Queue contract

Use three streams and one canonical group name:

- `sheshnaag:sandbox:work:standard` for ordinary queued execution;
- `sheshnaag:sandbox:work:detonation:libvirt` for Libvirt risky analysis;
- `sheshnaag:sandbox:work:detonation:lima` for Lima risky analysis;
- `sheshnaag:sandbox:workers:v1` as the consumer group on all streams.

The secure providers use separate streams. This prevents Redis from assigning
a Lima job to a Libvirt-only worker, or a Libvirt job to a Lima-only worker.

Every message includes a sorted `required_capabilities` list and a
`routing_version` value of `1`. The control plane derives this list from the
stored run provider, launch mode, and analysis mode. It does not accept worker
requirements from the HTTP client.

Standard work requires `docker`. Risky execute-mode work always requires
`pcap`, `zeek`, and `secure-mode`. A libvirt job also requires `linux`, `kvm`,
and `libvirt`; a Lima job also requires `lima`. A worker subscribes only to
streams for which it has a complete capability set for at least one routed job.
It also checks every message before it calls the execution handler.

All consumers use the same group on a given stream. Redis therefore assigns an
entry to one consumer only. A completed run is idempotent if a pending entry is
reclaimed after an acknowledgement failure.

## Provider contract

Risky analysis uses the selected sandbox profile provider when it is `lima` or
`libvirt`. The default secure file and email profiles use `libvirt`, which
matches the Linux KVM installation and health contract. Secure execution policy
accepts both `lima` and `libvirt`; it rejects Docker.

This change does not claim that KVM hardware exists. The detonation worker must
still prove the required tools and runtime flags on its host. Missing hardware
or tools remains a fail-closed deployment blocker.

## Worker data plane

The enrolled agent continues to execute the existing repository-native worker
handler. It must receive database and object-store configuration through the
private worker-host environment. Bootstrap will not return database or object
store secrets. The worker host must have private network access to Redis,
PostgreSQL, and the object store. Public exposure of these services is out of
contract.

## Compatibility and migration

- Keep `SANDBOX_WORK_STREAM` as an alias for the standard stream for source
  compatibility.
- New jobs use only the versioned streams and canonical group.
- Existing entries in the old stream are not silently replayed. Operators must
  inspect and resolve old pending work before cutover.
- The Compose worker defaults to `docker` capability and consumes standard work
  only.
- The enrolled agent must provide or detect the full detonation capability set
  before it can consume detonation work.

## Verification

Unit tests will prove stream selection, canonical group use, incompatible
worker rejection, matching-worker acceptance, provider selection, and
idempotent handling of a completed run. Existing worker and provider tests must
remain green.
