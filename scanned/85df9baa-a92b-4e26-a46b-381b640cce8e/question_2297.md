# Q2297: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `domain-separated hash` messages so `eval_exponent_interpolation` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Deliver later-round `domain-separated hash` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `domain-separated hash` data must never satisfy earlier-round `eval` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `domain-separated hash` / `eval` inputs, then assert whether downstream verification accepts an output that should have been rejected.
