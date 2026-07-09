# Q2598: Substitute app or public key

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and swap `old participant set` for attacker-chosen `coefficient commitment` while keeping the rest of `participants`, `session_id`, `protocol message timing` valid enough that `broadcast_success` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::broadcast_success`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `session_id`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `old participant set` outputs must be bound to the exact `coefficient commitment` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `broadcast_success`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
