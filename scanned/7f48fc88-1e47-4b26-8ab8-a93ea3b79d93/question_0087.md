# Q87: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `commitment hash` messages so `do_keyshare` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Deliver later-round `commitment hash` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `commitment hash` data must never satisfy earlier-round `domain_separator` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
