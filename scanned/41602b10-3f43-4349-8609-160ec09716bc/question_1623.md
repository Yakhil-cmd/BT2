# Q1623: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and reorder attacker-controlled `big_w share` messages so `fut_wrapper` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::fut_wrapper`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`
- Exploit idea: Deliver later-round `big_w share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `big_w share` data must never satisfy earlier-round `big_w share` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_w share` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
