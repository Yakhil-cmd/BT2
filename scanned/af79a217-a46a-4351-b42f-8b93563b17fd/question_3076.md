# Q3076: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and reorder attacker-controlled `rerandomized presignature` messages so `add_shares` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::add_shares`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `shares`, `protocol message timing`
- Exploit idea: Deliver later-round `rerandomized presignature` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `rerandomized presignature` data must never satisfy earlier-round `rerandomized presignature` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `rerandomized presignature` data into `add_shares`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
