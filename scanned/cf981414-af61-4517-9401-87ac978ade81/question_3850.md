# Q3850: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `interpolation set` into `eval_at_point` by controlling `point`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Capture a valid `interpolation set` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `interpolation set` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `interpolation set` / `at` inputs, then assert whether downstream verification accepts an output that should have been rejected.
