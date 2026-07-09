# Q1698: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and swap `signing nonces` for attacker-chosen `key package` while keeping the rest of `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing` valid enough that `sign_v1` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `signing nonces` outputs must be bound to the exact `key package` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
