# Q10: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `proof of knowledge` messages so `assert_key_invariants` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_key_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Deliver later-round `proof of knowledge` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `proof of knowledge` data must never satisfy earlier-round `public key commitments` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `assert_key_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
