# Q675: Omit context from rerandomization

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and exploit `challenge` so `received share` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `received share` helper material.
- Invariant to test: Derived or rerandomized `received share` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `challenge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
