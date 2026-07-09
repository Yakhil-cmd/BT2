# Q7: Omit context from rerandomization

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and exploit `assert_key_invariants` so `new participant set` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_key_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `new participant set` helper material.
- Invariant to test: Derived or rerandomized `new participant set` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `assert_key_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
