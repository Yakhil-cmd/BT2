# Q36: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `domain_separator` messages so `assert_reshare_keys_invariants` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_reshare_keys_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing`
- Exploit idea: Deliver later-round `domain_separator` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `domain_separator` data must never satisfy earlier-round `keys` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `assert_reshare_keys_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
