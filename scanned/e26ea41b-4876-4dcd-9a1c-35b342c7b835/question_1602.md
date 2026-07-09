# Q1602: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and use crafted batching inputs in `participants`, `presignature`, `msg_hash`, `protocol message timing` so `compute_signature_share` remaps one party's `w share` to another party's `max_malicious bound` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::compute_signature_share`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `w share` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`w share` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
