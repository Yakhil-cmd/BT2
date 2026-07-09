# Q344: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and reorder attacker-controlled `w share` messages so `do_presign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::do_presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Deliver later-round `w share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `w share` data must never satisfy earlier-round `rerandomized presignature` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
