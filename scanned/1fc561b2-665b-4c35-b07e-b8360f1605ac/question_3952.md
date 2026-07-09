# Q3952: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `domain-separated hash` variants into `generate_polynomial` so different honest parties bind different views of `polynomial commitment` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Feed different `domain-separated hash` values to different honest parties and test whether `polynomial commitment` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `domain-separated hash` / `polynomial commitment` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `domain-separated hash` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
