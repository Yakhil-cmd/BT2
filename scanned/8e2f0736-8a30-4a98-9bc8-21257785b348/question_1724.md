# Q1724: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and swap `key package` for attacker-chosen `coordinator-selected signer set` while keeping the rest of `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` valid enough that `sign_v2` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `key package` outputs must be bound to the exact `coordinator-selected signer set` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
