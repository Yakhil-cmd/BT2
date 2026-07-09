# Q2220: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `polynomial` messages so `batch_invert` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Deliver later-round `polynomial` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `polynomial` data must never satisfy earlier-round `polynomial commitment` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `polynomial` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
