# Q1746: Bypass proof binding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and control `participants`, `args`, `protocol message timing` so `presign` accepts a `key package` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Pair a proof/hash for one sender or session with a different `key package` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
