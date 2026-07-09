# Q1730: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and use crafted batching inputs in `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` so `sign_v2` remaps one party's `key package` to another party's `participant identifier` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `key package` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`key package` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
