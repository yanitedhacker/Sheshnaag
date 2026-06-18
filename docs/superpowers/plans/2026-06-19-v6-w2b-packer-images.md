# V6 Wave 2b — Packer Windows Golden Images

**Goal:** Document and wire the BYOL Packer pipeline that produces `sheshnaag-windows-golden` libvirt volumes for W2a detonation.

**Architecture:** Operators supply a Windows ISO; Packer builds an unattended golden image with Sysmon baseline. No images ship in-repo — templates and README only under `infra/packer/windows/`.

**Tech Stack:** HashiCorp Packer + QEMU/libvirt builder; Windows unattend + provisioning scripts.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Create | `infra/packer/windows/README.md` | BYOL build instructions, output volume name, worker flag |
| Create | `infra/packer/windows/windows-server.pkr.hcl` | Packer template (ISO → libvirt volume) |
| Reference | `app/lab/providers/libvirt_provider.py` | Consumes `sheshnaag-windows-golden` default image |
| Reference | `app/workers/sandbox_agent.py` | Advertises `windows-vm` capability flag |
| Reference | `docs/runbooks/v6/kickoff.md` | BYOL decision record |

---

## Build flow

```bash
export WINDOWS_ISO=/path/to/win11.iso
packer build -var "iso_url=$WINDOWS_ISO" infra/packer/windows/windows-server.pkr.hcl
```

Outputs: libvirt volume `sheshnaag-windows-golden`; pre-installed Sysmon, Windows Update baseline, optional Velociraptor agent.

---

## Acceptance for W2b

- README documents BYOL requirement and build command.
- Packer template produces importable libvirt volume on `sheshnaag-wk-01`.
- Worker bootstrap shows `windows-vm` in fleet registry after image install.
- End-to-end Windows detonation (specimen → telemetry → signed bundle) completes on staging host.
