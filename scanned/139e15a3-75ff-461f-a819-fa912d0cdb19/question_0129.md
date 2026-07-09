# Q129: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing` so repeated calls to `do_reshare` expose share-dependent structure in `commitment hash` or `new participant set` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::do_reshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing`
- Exploit idea: Query `commitment hash` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `commitment hash` or `new participant set`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `do_reshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
