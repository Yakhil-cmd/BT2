# Q3254: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `hash_app_id_with_pk binding` messages so `HDKG` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::HDKG`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `m`, `protocol message timing`
- Exploit idea: Deliver later-round `hash_app_id_with_pk binding` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `hash_app_id_with_pk binding` data must never satisfy earlier-round `encrypted CKD output` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `hash_app_id_with_pk binding` data into `HDKG`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
