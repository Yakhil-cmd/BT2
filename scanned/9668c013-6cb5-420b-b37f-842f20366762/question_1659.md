# Q1659: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::sign::sign(...)` and make repeated attacker-chosen queries around `sign` so the returned `w share` or `rerandomized presignature` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::robust_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `max_malicious`, `public_key`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `w share` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `w share` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
