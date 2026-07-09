# Q1976: Replay stale context

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and replay a stale `reshare` into `reshare` by controlling `old_participants`, `new_participants`, `old_threshold`, `new_threshold`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Capture a valid `reshare` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `reshare` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `reshare` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
