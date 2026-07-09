# Q298: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and use crafted batching inputs in `participants`, `threshold`, `protocol message timing` so `do_generation` remaps one party's `bit-matrix expansion` to another party's `presignature` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::do_generation`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `bit-matrix expansion` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`bit-matrix expansion` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `do_generation`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
