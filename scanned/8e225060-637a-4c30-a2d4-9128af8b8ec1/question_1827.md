# Q1827: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and swap `signing nonces` for attacker-chosen `key package` while keeping the rest of `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` valid enough that `sign` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `signing nonces` outputs must be bound to the exact `key package` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
