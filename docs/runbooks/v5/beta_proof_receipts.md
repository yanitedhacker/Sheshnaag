# Beta Proof Receipts

Use a proof receipt to connect one beta claim to exact evidence files. A receipt is valid for one proof class and one Git commit.

## Security boundary

- The acceptance host must pin `SHESHNAAG_PROOF_TRUST_FINGERPRINT`.
- A receipt key that is only declared inside a receipt is not trusted.
- Keep the private key outside the repository. Set file mode `0600`.
- Key possession gives authority to sign a release claim. Limit access to the release operator.
- Do not sign a `passed` receipt if a check is skipped, blocked, unavailable, or failed.
- Keep the receipt and its evidence files in one directory. The receipt uses relative artifact paths.
- A receipt does not replace external, isolated-worker, load, or field evidence.

## Proof classes

The beta gate needs these classes:

- `real_detonation`
- `ai_provider_matrix`
- `capability_audit`
- `stix_taxii`
- `autonomous_agent`
- `load_rehearsal`

## Create a trust key

```bash
PYTHONPATH=. python scripts/sheshnaag_proof_receipt.py keygen \
  --key /secure/path/sheshnaag-beta-proof.key
```

Record the returned fingerprint in the acceptance runtime:

```text
SHESHNAAG_PROOF_TRUST_FINGERPRINT=<64-character SHA-256 fingerprint>
```

## Create one receipt

Put the evidence log in the same directory as the output receipt. Use the exact commit that produced the evidence.

```bash
PYTHONPATH=. python scripts/sheshnaag_proof_receipt.py create \
  --proof-class autonomous_agent \
  --status passed \
  --git-commit "$(git rev-parse HEAD)" \
  --deployment-profile design_partner_beta \
  --artifact /evidence/beta/autonomous-agent/runtime.log \
  --check exact_action_run_committed=passed \
  --key /secure/path/sheshnaag-beta-proof.key \
  --issuer release-operator \
  --output /evidence/beta/autonomous-agent/receipt.json
```

Set the proof-class environment variable to the receipt path. For this example:

```text
SHESHNAAG_AUTONOMOUS_AGENT_PROOF=/evidence/beta/autonomous-agent/receipt.json
```

## Verify one receipt

```bash
PYTHONPATH=. python scripts/sheshnaag_proof_receipt.py verify \
  --receipt /evidence/beta/autonomous-agent/receipt.json \
  --proof-class autonomous_agent \
  --git-commit "$(git rev-parse HEAD)" \
  --trusted-fingerprint "$SHESHNAAG_PROOF_TRUST_FINGERPRINT"
```

The command returns nonzero if the signature, trust fingerprint, proof class, commit, pass state, evidence path, size, or SHA-256 is not valid.
