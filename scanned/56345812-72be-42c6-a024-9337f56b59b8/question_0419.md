# Q419: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and exploit `do_sign_coordinator_v1` so `participant identifier` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_coordinator_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `threshold`, `keygen_output`, `message`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `participant identifier` helper material.
- Invariant to test: Derived or rerandomized `participant identifier` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `do_sign_coordinator_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
