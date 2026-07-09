# Q2208: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `polynomial commitment` variants into `batch_invert` so different honest parties bind different views of `domain-separated hash` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Feed different `polynomial commitment` values to different honest parties and test whether `domain-separated hash` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `polynomial commitment` / `domain-separated hash` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `polynomial commitment` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
