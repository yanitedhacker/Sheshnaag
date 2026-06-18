# V6 Wave 2a — Libvirt Windows Provider

**Goal:** Add a KVM/libvirt sandbox provider for Windows detonation with Sysmon and ETW collectors, parity-of-evidence with the Docker-Kali Linux baseline.

**Architecture:** `LibvirtWindowsProvider` implements `LabProvider`; registered in `app/lab/provider_registry.py` alongside `docker_kali` and `lima`. Collectors registered in `app/lab/collectors/registry.py`. Simulated launch mode for CI; execute mode on KVM workers.

**Tech Stack:** libvirt/virsh (host), Python provider + collector plugins.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Create | `app/lab/providers/libvirt_provider.py` | Plan builder, snapshot/revert, domain lifecycle |
| Create | `app/lab/providers/__init__.py` | Package export |
| Create | `app/lab/collectors/sysmon.py` | Sysmon event export (simulated + execute) |
| Create | `app/lab/collectors/etw.py` | ETW Threat-Intelligence + Kernel-Process providers |
| Modify | `app/lab/collectors/registry.py` | Register `sysmon_events`, `etw_events` |
| Modify | `app/lab/provider_registry.py` | Register `LibvirtWindowsProvider` |
| Create | `tests/v6/test_libvirt_provider.py` | Plan shape + collector simulated mode |

---

## Provider contract

- Default image: `sheshnaag-windows-golden` (`SHESHNAAG_WINDOWS_IMAGE` override).
- Default collectors: `sysmon_events`, `etw_events`, `process_tree`, `file_diff`.
- Worker flag: `windows-vm` when virsh available.

---

## Acceptance for W2a

- `pytest tests/v6/test_libvirt_provider.py -q` passes.
- `ProviderRegistry.create("libvirt")` returns a working provider.
- Simulated detonation produces Sysmon + ETW artifact payloads in run output.
- W2b (Packer images) supplies the golden volume consumed by this provider.
