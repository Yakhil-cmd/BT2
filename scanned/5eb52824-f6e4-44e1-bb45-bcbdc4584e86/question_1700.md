# Q1700: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and reorder attacker-controlled `participant identifier` messages so `sign_v1` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Deliver later-round `participant identifier` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `participant identifier` data must never satisfy earlier-round `commitments_map` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
