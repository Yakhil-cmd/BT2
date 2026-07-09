# Q1038: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign::presign(...)` and reorder attacker-controlled `triple share` messages so `presign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Deliver later-round `triple share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `triple share` data must never satisfy earlier-round `OT transcript` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `triple share` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
