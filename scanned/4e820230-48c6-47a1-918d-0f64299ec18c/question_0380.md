# Q380: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and make repeated attacker-chosen queries around `do_sign_coordinator` so the returned `big_r share` or `w share` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `big_r share` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `big_r share` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_r share` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
