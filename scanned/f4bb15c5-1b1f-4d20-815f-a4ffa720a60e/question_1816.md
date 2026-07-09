# Q1816: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` so `fut_wrapper` reuses a transcript, hash, or domain-separation space for both `signing nonces` and `signing nonces`, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/redjubjub/sign.rs::fut_wrapper`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `signing nonces` and `signing nonces` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `signing nonces` namespace from every `signing nonces` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
