# 028 — TLSFP module integration

- Date: 2026-11-16
- Type: automatic

- The TLSFP state lives in the same per-connection context as JA4: the ex_data on the SSL object, in `c->pool`.
  The context is attached whenever the first ClientHello is seen, so JA4 and TLSFP fail independently.
- Variables:
  - `$clientfp_tlsfp`: the fingerprint, or empty when there is none.
  - `$clientfp_tlsfp_registry`: the ephemeral extension registry version, `1`, set only when `$clientfp_tlsfp`
    is. §13 asks that the version is stored with the fingerprint; a separate variable keeps the 49-character
    format intact.
- `clientfp off` empties both variables, as for JA4.
- When there is no TLSFP, an `info`-level log line gives the reason (malformed, out of memory, hash failure).
- `clientfp_tlsfp_compute` was added to the required symbols that `packager/verify.py` checks in each built
  nginx. A module source missing from the build then fails the build (the problem of decision 018).
