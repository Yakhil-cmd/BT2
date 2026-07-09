# Q3901: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `domain-separated hash` variants into `extend_with_identity` so different honest parties bind different views of `polynomial` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_identity`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial commitment`, `Lagrange coefficient`
- Exploit idea: Feed different `domain-separated hash` values to different honest parties and test whether `polynomial` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `domain-separated hash` / `polynomial` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_identity` that feeds crafted `domain-separated hash` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
