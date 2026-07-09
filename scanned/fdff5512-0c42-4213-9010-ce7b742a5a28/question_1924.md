# Q1924: Replay stale context

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and replay a stale `derived signing share` into `keygen` by controlling `participants`, `threshold`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Capture a valid `derived signing share` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `derived signing share` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived signing share` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
