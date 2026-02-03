# Patch Optimization Integration Plan (Cursor-Ready)

> **Target Repository**: `github.com/yanitedhacker/cve-threat-radar`
>
> This document is a **phase-wise, implementation-grade blueprint** intended to be fed directly into **Cursor** to extend CVE Threat Radar from *ML-based vulnerability prioritization* into a **full patch optimization and scheduling system**.
>
> This is not conceptual documentation. Every section maps to concrete code, data models, APIs, and UI changes.

---

## 0. Starting Assumptions (Do NOT Skip)

The existing project already provides:
- CVE ingestion (NVD, ExploitDB, MITRE)
- ML-based exploit likelihood prediction (XGBoost)
- Risk scoring per CVE
- Asset-aware vulnerability mapping
- Backend API + dashboard UI

Patch optimization will be built **on top of these outputs**, not in parallel.

---

## PHASE 1 — Patch Intelligence Foundation (Backend)

### Goal
Introduce *patch-aware data structures* without changing existing ML pipelines.

---

### 1.1 New Core Concepts

Add the concept of a **Patch** as a first-class entity (distinct from CVE).

Key principle:
> One CVE may have multiple patches, and one patch may remediate multiple CVEs.

---

### 1.2 Data Models

#### Patch Model

```json
{
  "patch_id": "PATCH-APACHE-2.4.59",
  "vendor": "apache",
  "affected_software": "httpd",
  "cve_ids": ["CVE-2025-XXXX"],
  "requires_reboot": true,
  "estimated_downtime_minutes": 15,
  "rollback_complexity": 0.6,
  "historical_failure_rate": 0.08,
  "released_at": "2025-01-20"
}
```

---

#### Asset–Patch Mapping

```json
{
  "asset_id": "edge-api-07",
  "patch_id": "PATCH-APACHE-2.4.59",
  "environment": "production",
  "maintenance_window": "02:00–04:00"
}
```

---

### 1.3 Repository Changes

Create a new module:

```
app/
  patch_intelligence/
    models.py
    repository.py
    validators.py
```

Responsibilities:
- Store patch metadata
- Link patches ↔ CVEs ↔ assets
- Expose patch data to optimization engine

No scoring logic in Phase 1.

---

## PHASE 2 — Patch Optimization Engine (Core Logic)

### Goal
Move from *risk scores* → *patch decisions*.

---

### 2.1 Optimization Dimensions (Mandatory)

Each patch must be evaluated across **five independent axes**:

1. **Exploit Likelihood (EL)**
   - Directly reused from existing ML model

2. **Impact Score (IS)**
   - RCE, LPE, InfoLeak
   - Auth required vs unauthenticated

3. **Asset Criticality Score (ACS)**
   - Business criticality
   - Blast radius
   - Exposure (internet-facing vs internal)

4. **Patch Cost Score (PCS)**
   - Reboot required
   - Downtime
   - Rollback complexity
   - Historical failure rate

5. **Time Pressure Multiplier (TPM)**
   - Non-linear urgency growth over time

All scores normalized to `[0,1]`.

---

### 2.2 Canonical Patch Priority Formula

```text
PatchPriority =
( EL × IS × ACS × TPM ) ÷ PCS
```

Interpretation rules:
- High priority + low cost → immediate patch
- High priority + high cost → scheduled patch
- Low priority + high cost → deferred

---

### 2.3 Engine Structure

Create:

```
app/
  patch_optimizer/
    scoring.py
    engine.py
    time_models.py
```

Responsibilities:
- Compute patch priority
- Explain score composition
- Produce patch decisions (not rankings)

---

### 2.4 Decision Output Schema

```json
{
  "patch_id": "PATCH-APACHE-2.4.59",
  "priority_score": 0.82,
  "decision": "PATCH_NOW",
  "expected_risk_reduction": 0.24,
  "justification": [
    "Weaponized exploit available",
    "Internet-facing asset",
    "Low rollback complexity"
  ]
}
```

---

## PHASE 3 — Patch Scheduling & Batching

### Goal
Optimize *when* patches are applied, not just *which*.

---

### 3.1 Batching Rules

Group patches by:
- Shared reboot requirement
- Same service dependency
- Same maintenance window

---

### 3.2 Scheduling Constraints

- Downtime budget per window
- Team capacity
- Environment (prod vs staging)

---

### 3.3 Scheduler Module

Create:

```
app/
  patch_scheduler/
    scheduler.py
    constraints.py
```

Initial implementation:
- Greedy heuristic maximizing risk reduction per downtime minute

Future upgrade:
- Knapsack / ILP formulation

---

### 3.4 Schedule Output

```json
{
  "window": "2025-02-03T02:00–04:00",
  "patches": ["PATCH-APACHE-2.4.59"],
  "total_downtime": 15,
  "risk_reduction": 0.31
}
```

---

## PHASE 4 — API Extensions

### Goal
Expose patch optimization as first-class API functionality.

---

### 4.1 New Endpoints

```
GET  /api/patches/priorities
GET  /api/patches/decisions
POST /api/patches/schedule
GET  /api/patches/{patch_id}
```

---

### 4.2 API Principles

- APIs return **decisions**, not raw scores
- Every response must include justification

---

## PHASE 5 — UI / UX Transformation

### Goal
Shift UI from *lists of CVEs* → *actionable remediation intelligence*.

---

### 5.1 Replace CVE Tables with Patch Cards

Each card shows:
- Patch decision (Now / Schedule / Defer)
- Risk before vs after
- Downtime cost
- Reasoning summary

---

### 5.2 Risk Delta Visualization

Mandatory UI elements:
- Risk reduction percentage
- Visual before/after bars

---

### 5.3 Time-Shift Views

Allow user to simulate:
- Patch now
- Delay 7 / 14 / 30 days

Show projected risk increase.

---

### 5.4 Dual UI Modes

- **Operator Mode**: patches, schedules, dependencies
- **Executive Mode**: risk trends, exposure reduction

Same data, different abstraction level.

---

## PHASE 6 — Feedback & Learning Loop

### Goal
Make the system self-correcting over time.

---

### 6.1 Track Outcomes

Persist:
- Patch failures
- Rollbacks
- Emergency patches
- Incidents tied to deferred patches

---

### 6.2 Learning Applications

Use feedback to:
- Reweight Patch Cost Score
- Adjust exploit signal trust
- Improve future decisions

---

## PHASE 7 — Advanced (Optional, High-End)

- Predictive exploitation curves
- Counterfactual analysis ("What if patched earlier?")
- Reinforcement learning for patch timing

---

## Final Success Criterion

The system must clearly answer:

> "What should we patch today to maximally reduce risk with minimal disruption — and why?"

If this question is not answerable directly from the UI, patch optimization is incomplete.

