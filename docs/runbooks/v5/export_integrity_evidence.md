# Export and Replay Integrity Evidence

**Branch:** `yanitedhacker/p0-to-beta`
**Date:** 2026-08-29

## Controls

Disclosure bundle export now gives each evidence row one explicit disposition:

- `excluded_by_policy`
- `included_unchanged`
- `included_redacted`

An excluded row is not written to the ZIP archive. Included JSON payloads use recursive sensitive-key redaction. The export manifest does not include the internal `storage_path`. The redaction log records each automatic JSON path. Manual redaction notes have the disposition `review_note_only`; they do not claim that a data change occurred.

Attachment policy values must be Boolean. Values such as the string `"false"` are rejected. This prevents a truthy string from enabling raw logs, PCAP, or screenshots.

Autonomous replay now has two bounds:

- The HTTP `limit` is 1 to 100.
- The service applies a hard maximum of 100 even for an internal caller.

Replay remains tenant-scoped. The response gives the explicit `bounded` replay disposition and reports the requested and maximum limits.

## Focused verification

The affected disclosure, autonomous, proof, and acceptance set completed:

```text
33 passed
```

The export test inspected the ZIP. It proved that a raw service-log row was absent, an included process payload had `api_key` and nested `password` replaced with `[REDACTED]`, and the manifest contained no internal storage path.

## Full local regression

The full local backend run completed with exit code 0:

```text
740 passed
135 skipped
0 failed
0 errors
```

The skipped tests are external integration tests controlled by repository policy. They are not qualification evidence.
