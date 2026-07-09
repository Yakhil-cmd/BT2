# Q3479: Interpolate on malicious subset

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and steer `public_key` so `derive_verifying_key` interpolates `private share` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `private share` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `private share`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `private share` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
