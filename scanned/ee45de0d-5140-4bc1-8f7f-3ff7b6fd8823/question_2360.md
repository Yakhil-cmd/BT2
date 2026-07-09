# Q2360: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `domain-separated hash` into `verify` by controlling `public_key`, `msg_hash`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Capture a valid `domain-separated hash` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `domain-separated hash` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `domain-separated hash` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
