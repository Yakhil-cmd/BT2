# Q3851: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `hash output` variants into `eval_at_point` so different honest parties bind different views of `polynomial commitment` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Feed different `hash output` values to different honest parties and test whether `polynomial commitment` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `hash output` / `polynomial commitment` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `hash output` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
