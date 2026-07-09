# Q101: Accept zero or identity input

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with attacker-chosen `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing` and make `do_keyshare` accept a zero or identity-valued `public key commitments` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `public key commitments` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `public key commitments` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `public key commitments` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
