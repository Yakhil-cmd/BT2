# Q1986: Omit context from rerandomization

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and exploit `reshare` so `public key` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `public key` helper material.
- Invariant to test: Derived or rerandomized `public key` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `public key` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
