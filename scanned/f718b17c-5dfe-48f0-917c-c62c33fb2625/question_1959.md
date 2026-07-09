# Q1959: Interpolate on malicious subset

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and steer `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key` so `refresh` interpolates `keygen output` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `keygen output` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `keygen output`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `keygen output` / `refresh` inputs, then assert whether downstream verification accepts an output that should have been rejected.
