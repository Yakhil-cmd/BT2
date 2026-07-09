# Q2385: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `nonce` into `prove_with_nonce` by controlling `transcript`, `statement`, `witness`, `nonce`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlog.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `nonce`
- Exploit idea: Capture a valid `nonce` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `nonce` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::prove_with_nonce` that feeds crafted `nonce` / `challenge` inputs, then assert whether downstream verification accepts an output that should have been rejected.
