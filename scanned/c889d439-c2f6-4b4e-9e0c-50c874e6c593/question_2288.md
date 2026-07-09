# Q2288: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `identifiers`, `shares`, `point` so `eval_exponent_interpolation` reuses a transcript, hash, or domain-separation space for both `Lagrange coefficient` and `serialized scalar`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `Lagrange coefficient` and `serialized scalar` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `Lagrange coefficient` namespace from every `serialized scalar` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `Lagrange coefficient` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
