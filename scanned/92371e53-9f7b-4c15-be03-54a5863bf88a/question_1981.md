# Q1981: Accept zero or identity input

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` with attacker-chosen `old_participants`, `new_participants`, `old_threshold`, `new_threshold` and make `reshare` accept a zero or identity-valued `keygen output` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Inject zero, identity, or empty-form `keygen output` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `keygen output` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `keygen output` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
