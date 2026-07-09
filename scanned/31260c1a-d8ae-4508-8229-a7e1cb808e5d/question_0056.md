# Q56: Mismatch commitment and share

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and pair a valid-looking `old participant set` with a different `keygen` reveal so `do_keygen` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Commit to one `old participant set` and reveal another `keygen` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `old participant set` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
