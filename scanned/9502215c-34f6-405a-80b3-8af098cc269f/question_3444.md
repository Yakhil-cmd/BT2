# Q3444: Replay stale context

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and replay a stale `derive` into `derive_signing_share` by controlling `private_share`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Capture a valid `derive` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `derive` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `derive` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
