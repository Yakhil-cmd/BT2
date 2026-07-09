# Q1790: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `threshold`, `keygen_output`, `protocol message timing` so `construct_key_package` reuses a transcript, hash, or domain-separation space for both `commitments_map` and `presignature context`, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/redjubjub/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `commitments_map` and `presignature context` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `commitments_map` namespace from every `presignature context` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
