# Q499: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and reorder attacker-controlled `participant identifier` messages so `do_sign_participant_v2` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_participant_v2`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `coordinator`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Deliver later-round `participant identifier` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `participant identifier` data must never satisfy earlier-round `signing nonces` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `do_sign_participant_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
