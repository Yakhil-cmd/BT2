# Q1839: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and make repeated attacker-chosen queries around `sign` so the returned `commitments_map` or `signing nonces` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `commitments_map` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `commitments_map` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
