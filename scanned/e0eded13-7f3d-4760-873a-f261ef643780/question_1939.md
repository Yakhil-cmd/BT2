# Q1939: Reuse stale public values

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and replay an old `public key` or cached `threshold` into `keygen` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `public key` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `public key` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
