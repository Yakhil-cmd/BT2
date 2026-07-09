# Q1778: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and reorder attacker-controlled `key package` messages so `construct_key_package` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Deliver later-round `key package` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `key package` data must never satisfy earlier-round `commitments_map` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
