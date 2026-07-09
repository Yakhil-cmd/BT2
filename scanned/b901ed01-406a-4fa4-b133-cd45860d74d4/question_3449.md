# Q3449: Accept zero or identity input

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` with attacker-chosen `private_share` and make `derive_signing_share` accept a zero or identity-valued `private share` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Inject zero, identity, or empty-form `private share` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `private share` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `private share` / `signing` inputs, then assert whether downstream verification accepts an output that should have been rejected.
