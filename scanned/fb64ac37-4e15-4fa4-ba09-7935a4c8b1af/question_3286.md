# Q3286: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and choose `m`, `protocol message timing` so repeated calls to `HID` expose share-dependent structure in `encrypted CKD output` or `app_pk` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::HID`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `m`, `protocol message timing`
- Exploit idea: Query `encrypted CKD output` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `encrypted CKD output` or `app_pk`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `encrypted CKD output` data into `HID`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
