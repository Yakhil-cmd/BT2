# Q1636: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and choose `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing` so `fut_wrapper` reuses a transcript, hash, or domain-separation space for both `participant set binding` and `max_malicious bound`, enabling Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::fut_wrapper`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `participant set binding` and `max_malicious bound` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `participant set binding` namespace from every `max_malicious bound` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant set binding` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
