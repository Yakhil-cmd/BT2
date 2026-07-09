# Q3105: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and use crafted batching inputs in `degree`, `protocol message timing` so `zero_secret_polynomial` remaps one party's `participant set binding` to another party's `rerandomized presignature` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::zero_secret_polynomial`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `degree`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `participant set binding` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`participant set binding` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant set binding` data into `zero_secret_polynomial`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
