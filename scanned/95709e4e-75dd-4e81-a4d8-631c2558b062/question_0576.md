# Q576: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and reorder attacker-controlled `signing nonces` messages so `do_sign_participant` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::do_sign_participant`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `coordinator`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Deliver later-round `signing nonces` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `signing nonces` data must never satisfy earlier-round `do_sign_participant` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `do_sign_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
