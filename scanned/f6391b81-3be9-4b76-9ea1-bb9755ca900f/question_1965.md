# Q1965: Reuse stale public values

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and replay an old `refresh` or cached `derived verifying key` into `refresh` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `refresh` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `refresh` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
