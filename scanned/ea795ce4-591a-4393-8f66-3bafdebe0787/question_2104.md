# Q2104: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `serialized scalar` into `compute` by controlling `val`, `r`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Capture a valid `serialized scalar` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `serialized scalar` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `serialized scalar` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
