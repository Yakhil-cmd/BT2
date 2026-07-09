# Q164: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `received share` messages so `verify_proof_of_knowledge` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing`
- Exploit idea: Deliver later-round `received share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `received share` data must never satisfy earlier-round `old participant set` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
