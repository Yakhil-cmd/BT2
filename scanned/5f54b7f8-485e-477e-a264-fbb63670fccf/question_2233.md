# Q2233: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `commit` into `commit_polynomial` by controlling `polynomial`, `polynomial commitment`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::commit_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial`, `polynomial commitment`
- Exploit idea: Capture a valid `commit` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `commit` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::commit_polynomial` that feeds crafted `commit` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
