# Q744: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `commitments`, `protocol message timing` so repeated calls to `public_key_from_commitments` expose share-dependent structure in `new participant set` or `domain_separator` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Query `new participant set` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `new participant set` or `domain_separator`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
