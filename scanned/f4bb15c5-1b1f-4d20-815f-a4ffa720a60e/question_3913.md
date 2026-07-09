# Q3913: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `serialized scalar` messages so `extend_with_identity` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_identity`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `serialized scalar`, `serialized group element`
- Exploit idea: Deliver later-round `serialized scalar` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `serialized scalar` data must never satisfy earlier-round `serialized group element` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_identity` that feeds crafted `serialized scalar` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
