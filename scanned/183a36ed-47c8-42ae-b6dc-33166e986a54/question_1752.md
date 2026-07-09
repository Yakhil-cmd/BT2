# Q1752: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and reorder attacker-controlled `participant identifier` messages so `presign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Deliver later-round `participant identifier` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `participant identifier` data must never satisfy earlier-round `nonce commitment` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
