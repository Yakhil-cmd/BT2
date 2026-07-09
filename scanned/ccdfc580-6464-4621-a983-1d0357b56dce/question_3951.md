# Q3951: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `domain-separated hash` into `generate_polynomial` by controlling `secret`, `degree`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Capture a valid `domain-separated hash` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `domain-separated hash` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `domain-separated hash` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
