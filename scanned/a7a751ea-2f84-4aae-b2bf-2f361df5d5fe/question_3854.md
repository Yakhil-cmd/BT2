# Q3854: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `point` so `eval_at_point` reuses a transcript, hash, or domain-separation space for both `interpolation set` and `Lagrange coefficient`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `interpolation set` and `Lagrange coefficient` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `interpolation set` namespace from every `Lagrange coefficient` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `interpolation set` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
