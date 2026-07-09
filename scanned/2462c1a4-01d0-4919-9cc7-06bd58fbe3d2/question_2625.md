# Q2625: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `old participant set` messages so `generate_coefficient_commitment` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::generate_coefficient_commitment`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret_coefficients`, `protocol message timing`
- Exploit idea: Deliver later-round `old participant set` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `old participant set` data must never satisfy earlier-round `proof of knowledge` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `generate_coefficient_commitment`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
