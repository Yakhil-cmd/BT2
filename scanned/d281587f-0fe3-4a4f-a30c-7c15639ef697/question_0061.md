# Q61: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `new participant set` messages so `do_keygen` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Deliver later-round `new participant set` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `new participant set` data must never satisfy earlier-round `domain_separator` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
