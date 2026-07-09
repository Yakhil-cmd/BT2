# Q472: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and swap `signing nonces` for attacker-chosen `participant identifier` while keeping the rest of `coordinator`, `threshold`, `keygen_output`, `message`, `protocol message timing` valid enough that `do_sign_participant_v1` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_participant_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `coordinator`, `threshold`, `keygen_output`, `message`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `signing nonces` outputs must be bound to the exact `participant identifier` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `do_sign_participant_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
