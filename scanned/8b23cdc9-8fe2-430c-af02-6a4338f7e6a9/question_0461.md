# Q461: Collide transcript domains

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and choose `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing` so `do_sign_coordinator_v2` reuses a transcript, hash, or domain-separation space for both `coordinator` and `coordinator`, enabling Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_coordinator_v2`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `coordinator` and `coordinator` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `coordinator` namespace from every `coordinator` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator` data into `do_sign_coordinator_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
