# Q3150: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and swap `participant identifier` for attacker-chosen `nonce commitment` while keeping the rest of `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` valid enough that `fut_wrapper_v2` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::fut_wrapper_v2`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `participant identifier` outputs must be bound to the exact `nonce commitment` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `fut_wrapper_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
