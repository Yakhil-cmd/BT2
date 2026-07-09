# Q1736: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and make repeated attacker-chosen queries around `sign_v2` so the returned `commitments_map` or `signing nonces` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `commitments_map` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `commitments_map` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
