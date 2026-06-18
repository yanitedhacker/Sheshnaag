# Migration Guide: V5 → V6

## Overview

V6 activates full-spectrum offensive capabilities under capability policy, adds a Windows libvirt provider, and extends the Authorization Center for multi-reviewer quorum. V5 API paths remain under `/api/v5/`; new offensive surfaces use `/api/v6/`.

**Kickoff record:** [docs/runbooks/v6/kickoff.md](../runbooks/v6/kickoff.md)

## Database migrations

Run Alembic through V6 head:

```bash
alembic upgrade head
```

New revisions (in order):

- `v6a01` — `exploit_validation_runs` table; drops legacy `analysis_cases.status`
- `v6a02` — seeds `purple.replay` and `research.write` permissions

## Breaking changes

| Area | V5 | V6 |
|------|----|----|
| Offensive capabilities | Policy hooks only (`off`) | Active with dual / dual_plus_admin review |
| Windows targets | Not supported | `libvirt` provider + Sysmon/ETW collectors |
| Authorization issuance | Single reviewer default | Quorum enforced per `review_kind` |
| Case status | Legacy `analysis_cases.status` column | Removed — use `lifecycle_state` only |
| Frontend routes | 24 gated surfaces | + Purple Team, Research Workbench |

## Operator steps

1. **Review kickoff decisions** — BYOL Windows ISO, KVM host assignment, ART attribution ([kickoff.md](../runbooks/v6/kickoff.md)).
2. **Apply migrations** — `alembic upgrade head` through `v6a02`.
3. **Build golden image** — follow `infra/packer/windows/README.md` on KVM workers.
4. **Enroll workers** — confirm `windows-vm` flag in Worker Fleet after libvirt install.
5. **Seed permissions** — migration `v6a02` grants `purple.replay` / `research.write` to `senior_analyst` and `lab_lead`.
6. **Issue offensive authorizations** — use Authorization Center dual-reviewer flow for each capability.
7. **Verify gate** — follow [V6 smoke runbook](../runbooks/v6/smoke.md).

## New environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SHESHNAAG_WINDOWS_IMAGE` | `sheshnaag-windows-golden` | Libvirt volume name |
| `SHESHNAAG_LIBVIRT_URI` | `qemu:///system` | Worker libvirt connection |
| `SHESHNAAG_ENABLE_SYSMON` | `1` | Toggle Sysmon collector |

## Rollback

V6 migrations are forward-only. Rollback requires restore from pre-V6 DB snapshot. Dropping `analysis_cases.status` is irreversible — ensure V5 lifecycle migration completed before upgrading.

## Deferred to V7

- CVE/CNA coordination workflow
- Publication ledger and external intel publishing
- Zenodo reproducibility packages
