# Q1745: Swap participant ordering

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` with crafted `participants`, `args`, `protocol message timing` and exploit `presign` so participant ordering or identifier mapping for `presign` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `presign` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
