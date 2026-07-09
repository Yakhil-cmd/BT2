# Q91: Desync batched indices

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use crafted batching inputs in `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing` so `do_keyshare` remaps one party's `proof of knowledge` to another party's `session_id` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `proof of knowledge` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`proof of knowledge` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
