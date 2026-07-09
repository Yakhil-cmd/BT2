# Q1565: Swap participant ordering

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` with crafted `participants`, `args`, `protocol message timing` and exploit `presign` so participant ordering or identifier mapping for `big_w share` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `big_w share` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_w share` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
