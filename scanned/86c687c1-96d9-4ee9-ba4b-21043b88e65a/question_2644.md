# Q2644: Bypass proof binding

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and control `threshold`, `commitment_i`, `protocol message timing` so `insert_identity_if_missing` accepts a `old participant set` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::insert_identity_if_missing`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `threshold`, `commitment_i`, `protocol message timing`
- Exploit idea: Pair a proof/hash for one sender or session with a different `old participant set` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `insert_identity_if_missing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
