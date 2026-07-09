# Q1934: Omit context from rerandomization

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and exploit `keygen` so `derived verifying key` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `derived verifying key` helper material.
- Invariant to test: Derived or rerandomized `derived verifying key` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived verifying key` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
