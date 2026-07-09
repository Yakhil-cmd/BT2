# Q550: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and reorder attacker-controlled `key package` messages so `do_sign_coordinator` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::do_sign_coordinator`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Deliver later-round `key package` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `key package` data must never satisfy earlier-round `nonce commitment` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
