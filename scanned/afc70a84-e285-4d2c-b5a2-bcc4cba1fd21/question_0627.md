# Q627: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `ckd` messages so `do_ckd_coordinator` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_coordinator`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Deliver later-round `ckd` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `ckd` data must never satisfy earlier-round `big_c` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `ckd` data into `do_ckd_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
