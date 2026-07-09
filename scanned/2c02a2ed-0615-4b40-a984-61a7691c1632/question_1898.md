# Q1898: Replay stale context

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and replay a stale `encrypted CKD output` into `run_ckd_protocol` by controlling `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::run_ckd_protocol`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Capture a valid `encrypted CKD output` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `encrypted CKD output` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `encrypted CKD output` data into `run_ckd_protocol`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
