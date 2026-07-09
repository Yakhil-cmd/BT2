# Q2310: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `interpolation` variants into `eval_interpolation` so different honest parties bind different views of `serialized group element` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Feed different `interpolation` values to different honest parties and test whether `serialized group element` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `interpolation` / `serialized group element` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `interpolation` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
