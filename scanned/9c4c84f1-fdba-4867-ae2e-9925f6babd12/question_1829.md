# Q1829: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and reorder attacker-controlled `presignature context` messages so `sign` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Deliver later-round `presignature context` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `presignature context` data must never satisfy earlier-round `sign` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature context` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
