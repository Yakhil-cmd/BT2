# Q3926: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `domain-separated hash` variants into `extend_with_zero` so different honest parties bind different views of `zero` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial commitment`, `Lagrange coefficient`
- Exploit idea: Feed different `domain-separated hash` values to different honest parties and test whether `zero` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `domain-separated hash` / `zero` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `domain-separated hash` / `zero` inputs, then assert whether downstream verification accepts an output that should have been rejected.
