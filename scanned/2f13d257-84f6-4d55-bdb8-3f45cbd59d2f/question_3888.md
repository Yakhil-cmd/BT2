# Q3888: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `serialized scalar` messages so `eval_at_zero` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `serialized scalar`, `serialized group element`
- Exploit idea: Deliver later-round `serialized scalar` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `serialized scalar` data must never satisfy earlier-round `polynomial commitment` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_zero` that feeds crafted `serialized scalar` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
