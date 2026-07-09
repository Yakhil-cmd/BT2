# Q365: Mismatch commitment and share

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and pair a valid-looking `w share` with a different `big_r share` reveal so `do_sign_coordinator` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Commit to one `w share` and reveal another `big_r share` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `w share` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
