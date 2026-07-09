# Q2285: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `domain-separated hash` variants into `eval_exponent_interpolation` so different honest parties bind different views of `interpolation set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Feed different `domain-separated hash` values to different honest parties and test whether `interpolation set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `domain-separated hash` / `interpolation set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `domain-separated hash` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
