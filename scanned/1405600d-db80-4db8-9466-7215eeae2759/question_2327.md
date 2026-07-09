# Q2327: Abuse normalization ambiguity

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `identifiers`, `shares`, `point` so `eval_interpolation` normalizes two semantically different `eval` states into one accepted output, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Construct inputs that normalize to the same accepted form while representing different semantic signer or key states.
- Invariant to test: Normalization must not collapse two distinct `eval` states into one accepted result.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `eval` / `interpolation` inputs, then assert whether downstream verification accepts an output that should have been rejected.
