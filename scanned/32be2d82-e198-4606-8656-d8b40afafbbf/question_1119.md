# Q1119: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and use crafted batching inputs in `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing` so `sign` remaps one party's `sigma share` to another party's `Beaver triple` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `sigma share` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`sigma share` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
