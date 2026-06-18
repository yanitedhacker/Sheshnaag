# V6 Windows golden image pipeline (BYOL)

Operators supply their own Windows ISO (BYOL). This directory contains Packer templates only — no redistributable images ship in the repo.

## Build

```bash
export WINDOWS_ISO=/path/to/win11.iso
packer build -var "iso_url=$WINDOWS_ISO" windows-server.pkr.hcl
```

## Outputs

- `sheshnaag-windows-golden` libvirt volume name
- Pre-installed: Sysmon, Velociraptor agent (optional), Windows Update baseline

## Worker flag

Workers with KVM + libvirt advertise `windows-vm` in `capability_flags` during bootstrap.
