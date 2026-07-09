# Q1881: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `app_pk` messages so `compute_signature_share` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::compute_signature_share`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Deliver later-round `app_pk` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `app_pk` data must never satisfy earlier-round `signature` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
