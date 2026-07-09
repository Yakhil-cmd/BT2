# Q374: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and use crafted batching inputs in `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing` so `do_sign_coordinator` remaps one party's `w share` to another party's `w share` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `w share` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`w share` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
