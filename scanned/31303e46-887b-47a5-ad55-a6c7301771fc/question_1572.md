# Q1572: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and reorder attacker-controlled `presign package` messages so `presign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Deliver later-round `presign package` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `presign package` data must never satisfy earlier-round `max_malicious bound` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign package` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
