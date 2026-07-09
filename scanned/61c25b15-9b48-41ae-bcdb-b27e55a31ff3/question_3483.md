# Q3483: Reorder rounds

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and reorder attacker-controlled `keygen output` messages so `derive_verifying_key` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Deliver later-round `keygen output` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `keygen output` data must never satisfy earlier-round `verifying` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `keygen output` / `verifying` inputs, then assert whether downstream verification accepts an output that should have been rejected.
