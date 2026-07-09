# Q2007: Accept zero or identity input

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with attacker-chosen `secret`, `old_reshare_package`, `protocol message timing` and make `assert_keyshare_inputs` accept a zero or identity-valued `new participant set` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::assert_keyshare_inputs`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `new participant set` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `new participant set` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `assert_keyshare_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
