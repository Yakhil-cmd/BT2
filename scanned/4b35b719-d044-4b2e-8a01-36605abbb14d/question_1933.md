# Q1933: Interpolate on malicious subset

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and steer `participants`, `threshold` so `keygen` interpolates `private share` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `private share` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `private share`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `private share` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
