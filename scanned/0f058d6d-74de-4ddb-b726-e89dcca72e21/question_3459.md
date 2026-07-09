# Q3459: Reuse stale public values

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and replay an old `signing` or cached `threshold` into `derive_signing_share` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `signing` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `signing` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
