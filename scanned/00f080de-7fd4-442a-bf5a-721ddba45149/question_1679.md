# Q1679: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and use crafted batching inputs in `threshold`, `signing_share`, `verifying_key`, `protocol message timing` so `construct_key_package` remaps one party's `key package` to another party's `key package` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `key package` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`key package` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
