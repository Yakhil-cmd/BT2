# Q3101: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and reorder attacker-controlled `polynomial` messages so `zero_secret_polynomial` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::zero_secret_polynomial`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `degree`, `protocol message timing`
- Exploit idea: Deliver later-round `polynomial` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `polynomial` data must never satisfy earlier-round `secret` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `polynomial` data into `zero_secret_polynomial`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
