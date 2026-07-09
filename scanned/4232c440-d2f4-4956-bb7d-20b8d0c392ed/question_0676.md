# Q676: Substitute app or public key

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and swap `proof of knowledge` for attacker-chosen `domain_separator` while keeping the rest of `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing` valid enough that `challenge` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `proof of knowledge` outputs must be bound to the exact `domain_separator` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `challenge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
