# Q1649: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::sign::sign(...)` and reorder attacker-controlled `big_r share` messages so `sign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::robust_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `max_malicious`, `public_key`, `protocol message timing`
- Exploit idea: Deliver later-round `big_r share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `big_r share` data must never satisfy earlier-round `participant set binding` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_r share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
