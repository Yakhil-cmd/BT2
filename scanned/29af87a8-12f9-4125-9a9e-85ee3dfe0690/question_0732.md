# Q732: Desync batched indices

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use crafted batching inputs in `commitments`, `protocol message timing` so `public_key_from_commitments` remaps one party's `new participant set` to another party's `old participant set` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `new participant set` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`new participant set` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
