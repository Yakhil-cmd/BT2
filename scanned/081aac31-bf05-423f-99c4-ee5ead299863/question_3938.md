# Q3938: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `polynomial` messages so `extend_with_zero` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `serialized scalar`, `serialized group element`
- Exploit idea: Deliver later-round `polynomial` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `polynomial` data must never satisfy earlier-round `Lagrange coefficient` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `polynomial` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
