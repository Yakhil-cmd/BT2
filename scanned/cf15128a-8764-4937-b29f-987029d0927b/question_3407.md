# Q3407: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `mod` messages so `from_be_bytes_mod_order` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_be_bytes_mod_order`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Deliver later-round `mod` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `mod` data must never satisfy earlier-round `encrypted CKD output` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `mod` data into `from_be_bytes_mod_order`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
