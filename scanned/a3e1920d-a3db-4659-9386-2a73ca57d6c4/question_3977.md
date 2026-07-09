# Q3977: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `Lagrange coefficient` into `set_non_identity_constant` by controlling `v`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Capture a valid `Lagrange coefficient` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `Lagrange coefficient` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `Lagrange coefficient` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
