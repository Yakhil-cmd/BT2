# Q2078: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `Lagrange coefficient` into `commit` by controlling `val`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::commit`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Capture a valid `Lagrange coefficient` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `Lagrange coefficient` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::commit` that feeds crafted `Lagrange coefficient` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
