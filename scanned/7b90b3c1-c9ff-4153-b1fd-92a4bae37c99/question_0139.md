# Q139: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `commitment` messages so `verify_commitment_hash` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::verify_commitment_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Deliver later-round `commitment` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `commitment` data must never satisfy earlier-round `coefficient commitment` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment` data into `verify_commitment_hash`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
