# Q723: Mismatch commitment and share

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and pair a valid-looking `commitment hash` with a different `received share` reveal so `public_key_from_commitments` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Commit to one `commitment hash` and reveal another `received share` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `commitment hash` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
