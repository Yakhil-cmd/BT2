# Q3470: Replay stale context

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and replay a stale `threshold` into `derive_verifying_key` by controlling `public_key`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Capture a valid `threshold` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `threshold` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `threshold` / `derive` inputs, then assert whether downstream verification accepts an output that should have been rejected.
