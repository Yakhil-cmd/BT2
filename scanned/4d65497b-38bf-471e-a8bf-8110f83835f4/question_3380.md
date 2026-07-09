# Q3380: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and swap `encrypted CKD output` for attacker-chosen `big_y` while keeping the rest of `scalar`, `Self`, `protocol message timing` valid enough that `invert` produces an accepted unauthorized output, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::invert`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `scalar`, `Self`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `encrypted CKD output` outputs must be bound to the exact `big_y` selected by the honest protocol run.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `encrypted CKD output` data into `invert`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
