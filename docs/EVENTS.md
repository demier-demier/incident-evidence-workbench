# Normalized event contract v1

One UTF-8 JSON object per nonempty line. Blank lines are allowed and retain their line positions for source references. CRLF input is accepted. There is no JSON array wrapper, comments, duplicate object keys, coercion, extra fields or nonfinite numbers. An invalid line rejects the whole submission; partial analysis is not returned.

| Boundary | Limit |
|---|---|
| Input bytes | 262,144 (256 KiB) |
| Nonempty event lines | 1,000; duplicate lines count toward the input limit |
| Bytes per line | 4,096, excluding LF |
| String field length | 1–160 characters, nonblank, no C0/C1 controls or surrogate characters |
| Timestamp | RFC3339 with seconds and timezone; at most six fractional digits; UTC year 2000–2100 |
| Source IP | IPv4 or IPv6 literal; no hostname or zone suffix |
| Returned records | Integer 0–1,000,000; booleans are not integers |

All event types require `timestamp`, `tenant`, `actor`, `type`, `source_ip`.

| Type | Additional fields |
|---|---|
| `auth_failure` | Optional `session` string |
| `auth_success` | Optional `session` string; required for session-based rules to match |
| `role_change` | Required `session`, `old_role`, `new_role`; roles are `viewer`, `member`, `admin`, `owner` |
| `token_use` | Required `token_id` reference string and `expected_source` boolean |
| `data_access` | Required `session`, `resource`, `classification` (`public`, `internal`, `restricted`), `authorized` boolean, `records` integer |

`actor` on a role change means the **identity receiving the role**, using the same authenticated identity as the matched authentication record. The format does not model the granting administrator. Real adapters need to preserve that distinction in their own records; the workbench asks the analyst to check the granting identity externally.

`token_id` is a harmless reference label, never a token credential. `expected_source` is an externally supplied, trusted policy annotation; it is not inferred by the workbench. `authorized` means the actor was authorized by the applicable policy; `records` counts records actually returned. A denied access that returned zero records is intentionally not R04. Missing or unknown policy decisions are not replaced with `false` or `true`; such source events cannot be represented by this narrow version without a trustworthy adapter.

Identity fields compare exactly, including case and whitespace. Only timestamps and IP representations are normalized. Tenant and actor are always part of correlation keys. Session and token references are not assumed globally unique.

## Evidence identity and ordering

The normalized event is serialized as ASCII JSON with sorted keys and compact separators, then hashed with SHA-256. `evidence_id` is `ev_` plus that full digest. Reordering keys, whitespace, equivalent timezone representations and equivalent IPv6 representations therefore preserve the ID. Duplicate events collect all source line numbers, and cannot inflate a failure threshold.

`input_sha256` is a SHA-256 hash of the entire original UTF-8 byte sequence. It changes with whitespace or input order. Raw source files are not kept by the server. Normalized events and source line numbers are included in exports. Hashes are useful for reproducibility and comparison; without trusted source signatures/storage, a malicious producer can replace an input and recompute all hashes.

Events sort by normalized UTC timestamp then evidence ID. Equal timestamps cannot establish the strict temporal order required by any rule. No event is inferred to have occurred merely because it follows another line in the file.
