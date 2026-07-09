# Q400: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and use crafted batching inputs in `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing` so `do_sign_participant` remaps one party's `rerandomized presignature` to another party's `rerandomized presignature` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_participant`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `rerandomized presignature` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`rerandomized presignature` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `rerandomized presignature` data into `do_sign_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
