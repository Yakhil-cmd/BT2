# Q1750: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and swap `signing nonces` for attacker-chosen `signing nonces` while keeping the rest of `participants`, `args`, `protocol message timing` valid enough that `presign` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `signing nonces` outputs must be bound to the exact `signing nonces` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
