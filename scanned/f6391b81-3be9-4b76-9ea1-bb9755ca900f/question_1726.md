# Q1726: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and reorder attacker-controlled `key package` messages so `sign_v2` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Deliver later-round `key package` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `key package` data must never satisfy earlier-round `signing nonces` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
