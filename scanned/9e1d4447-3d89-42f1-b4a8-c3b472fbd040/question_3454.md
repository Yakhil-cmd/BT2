# Q3454: Omit context from rerandomization

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and exploit `derive_signing_share` so `threshold` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `threshold` helper material.
- Invariant to test: Derived or rerandomized `threshold` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `threshold` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
