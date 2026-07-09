# Q528: Desync batched indices

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and use crafted batching inputs in `participants`, `signing_share`, `protocol message timing` so `do_presign` remaps one party's `commitments_map` to another party's `presignature context` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::do_presign`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `signing_share`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `commitments_map` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`commitments_map` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
