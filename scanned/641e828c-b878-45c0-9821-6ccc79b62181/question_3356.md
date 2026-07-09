# Q3356: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `app_pk` messages so `hash_to_scalar` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::hash_to_scalar`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `domain`, `msg`, `protocol message timing`
- Exploit idea: Deliver later-round `app_pk` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `app_pk` data must never satisfy earlier-round `big_c` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `hash_to_scalar`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
