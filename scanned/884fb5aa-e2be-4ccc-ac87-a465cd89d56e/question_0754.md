# Q754: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `validate_received_share` messages so `validate_received_share` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::validate_received_share`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitment`, `from`, `signing_share_from`, `protocol message timing`
- Exploit idea: Deliver later-round `validate_received_share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `validate_received_share` data must never satisfy earlier-round `old participant set` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `validate_received_share` data into `validate_received_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
