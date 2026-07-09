# Q1975: Validate same bytes under two meanings

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and submit the same raw `public key` bytes under two semantic interpretations so `refresh` accepts both paths even though only one should be valid, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Submit identical raw bytes for `public key` under two semantic interpretations and test whether both verification paths accept them.
- Invariant to test: The same `public key` bytes must not validate under multiple semantic domains, roles, or curve/group interpretations.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `public key` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
