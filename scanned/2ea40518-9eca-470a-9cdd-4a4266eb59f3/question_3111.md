# Q3111: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and make repeated attacker-chosen queries around `zero_secret_polynomial` so the returned `big_w share` or `big_r share` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::zero_secret_polynomial`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `degree`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `big_w share` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `big_w share` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_w share` data into `zero_secret_polynomial`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
