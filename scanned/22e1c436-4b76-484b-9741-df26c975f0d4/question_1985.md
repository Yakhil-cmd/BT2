# Q1985: Interpolate on malicious subset

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and steer `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so `reshare` interpolates `keygen output` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `keygen output` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `keygen output`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `keygen output` / `private share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
