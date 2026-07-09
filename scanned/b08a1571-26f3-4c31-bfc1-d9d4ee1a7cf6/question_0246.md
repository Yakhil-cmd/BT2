# Q246: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and use crafted batching inputs in `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing` so `do_sign_coordinator` remaps one party's `presignature` to another party's `coordinator` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `presignature` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`presignature` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `presignature` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
