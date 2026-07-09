# Q1033: Mismatch commitment and share

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign::presign(...)` and pair a valid-looking `presign` with a different `MTA package` reveal so `presign` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Commit to one `presign` and reveal another `MTA package` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `presign` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
