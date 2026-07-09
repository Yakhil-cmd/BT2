# Q1115: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and reorder attacker-controlled `beta share` messages so `sign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Deliver later-round `beta share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `beta share` data must never satisfy earlier-round `beta share` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `beta share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
