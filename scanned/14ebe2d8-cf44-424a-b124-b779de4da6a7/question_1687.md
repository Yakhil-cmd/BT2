# Q1687: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `threshold`, `signing_share`, `verifying_key`, `protocol message timing` so `construct_key_package` reuses a transcript, hash, or domain-separation space for both `coordinator-selected signer set` and `commitments_map`, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `coordinator-selected signer set` and `commitments_map` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `coordinator-selected signer set` namespace from every `commitments_map` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
