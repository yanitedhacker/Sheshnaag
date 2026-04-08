# Sheshnaag Safety Policy

## Product Boundary

Project Sheshnaag is a defensive vulnerability research lab. It is not an offensive execution platform.

## Allowed

- controlled validation of vulnerability conditions
- evidence collection inside constrained local validation environments
- defensive detection and mitigation generation
- provenance capture and disclosure bundle packaging
- analyst review and contribution tracking

## Not Allowed

- autonomous target discovery against third-party assets
- exploit brokerage or exploit marketplace behavior
- phishing, credential harvesting, or social engineering workflows
- public release of turnkey weaponized exploit content
- one-click compromise workflows against customer or public infrastructure

## Current Validation Model

The current implementation uses a constrained Kali-on-Docker path as the first Sheshnaag release model.

- provider plans default to read-only filesystem behavior
- capabilities are dropped by default
- security options are explicit
- network policy is modeled as default-deny unless allowlisted
- workspaces are ephemeral
- sensitive runs require analyst acknowledgement

This is a practical first release model, not the final secure-mode target.

## Future Secure Mode

Later phases should add a VM-grade Linux guest provider with stronger snapshot and revert semantics. That future mode should tighten isolation further without changing the recipe/run abstraction presented to the rest of the system.

## Evidence and Export Rules

- every meaningful output should point back to run context and provenance
- evidence should be reviewed before defensive artifact promotion
- disclosure bundles should be signed and attributable
- out-of-scope or unsafe exports should remain blocked by policy
