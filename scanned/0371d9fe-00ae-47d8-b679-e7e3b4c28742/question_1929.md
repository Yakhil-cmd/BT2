# Q1929: Accept zero or identity input

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` with attacker-chosen `participants`, `threshold` and make `keygen` accept a zero or identity-valued `keygen output` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Inject zero, identity, or empty-form `keygen output` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `keygen output` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `keygen output` / `derived signing share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
