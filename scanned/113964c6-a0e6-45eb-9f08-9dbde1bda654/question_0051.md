# Q51: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing` so repeated calls to `assert_reshare_keys_invariants` expose share-dependent structure in `proof of knowledge` or `proof of knowledge` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::assert_reshare_keys_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing`
- Exploit idea: Query `proof of knowledge` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `proof of knowledge` or `proof of knowledge`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `assert_reshare_keys_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
