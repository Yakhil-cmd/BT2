# Q1949: Validate same bytes under two meanings

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and submit the same raw `participant set` bytes under two semantic interpretations so `keygen` accepts both paths even though only one should be valid, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Submit identical raw bytes for `participant set` under two semantic interpretations and test whether both verification paths accept them.
- Invariant to test: The same `participant set` bytes must not validate under multiple semantic domains, roles, or curve/group interpretations.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `participant set` / `keygen` inputs, then assert whether downstream verification accepts an output that should have been rejected.
