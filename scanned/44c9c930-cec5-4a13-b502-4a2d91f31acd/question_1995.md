# Q1995: Reuse helper output under new signer set

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and carry a previously valid `keygen output` helper output into a different participant set or threshold context where `reshare` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `keygen output` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `keygen output` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
