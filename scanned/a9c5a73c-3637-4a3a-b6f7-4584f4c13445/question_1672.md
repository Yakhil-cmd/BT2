# Q1672: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and exploit `construct_key_package` so `nonce commitment` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `nonce commitment` helper material.
- Invariant to test: Derived or rerandomized `nonce commitment` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
