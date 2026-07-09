# Q220: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and use crafted batching inputs in `participants`, `args`, `protocol message timing` so `do_presign` remaps one party's `big_r` to another party's `presignature` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/presign.rs::do_presign`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `big_r` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`big_r` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `big_r` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
