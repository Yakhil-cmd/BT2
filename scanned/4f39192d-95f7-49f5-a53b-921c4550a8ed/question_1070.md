# Q1070: Reuse helper output under new signer set

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and carry a previously valid `big_r` helper output into a different participant set or threshold context where `compute_signature_share` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::compute_signature_share`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `big_r` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
