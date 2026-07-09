# Q1950: Replay stale context

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and replay a stale `refresh` into `refresh` by controlling `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Capture a valid `refresh` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `refresh` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `refresh` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
