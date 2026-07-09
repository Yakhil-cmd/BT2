# Q103: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing` so repeated calls to `do_keyshare` expose share-dependent structure in `proof of knowledge` or `session_id` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Query `proof of knowledge` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `proof of knowledge` or `session_id`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
