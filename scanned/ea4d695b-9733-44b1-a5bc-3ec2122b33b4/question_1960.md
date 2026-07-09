# Q1960: Omit context from rerandomization

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and exploit `refresh` so `derived signing share` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `derived signing share` helper material.
- Invariant to test: Derived or rerandomized `derived signing share` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `derived signing share` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
