# Q364: Bypass proof binding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and control `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing` so `do_sign_coordinator` accepts a `coordinator` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Pair a proof/hash for one sender or session with a different `coordinator` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
