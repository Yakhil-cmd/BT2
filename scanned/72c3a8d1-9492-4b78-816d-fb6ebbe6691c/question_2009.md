# Q2009: Bypass proof binding

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and control `secret`, `old_reshare_package`, `protocol message timing` so `assert_keyshare_inputs` accepts a `public key commitments` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_keyshare_inputs`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Pair a proof/hash for one sender or session with a different `public key commitments` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `public key commitments` data into `assert_keyshare_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
