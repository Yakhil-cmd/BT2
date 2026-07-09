# Q3439: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `okm`, `Self`, `protocol message timing` so repeated calls to `from_okm` expose share-dependent structure in `from` or `scalar wrapper` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_okm`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `okm`, `Self`, `protocol message timing`
- Exploit idea: Query `from` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `from` or `scalar wrapper`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `from` data into `from_okm`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
