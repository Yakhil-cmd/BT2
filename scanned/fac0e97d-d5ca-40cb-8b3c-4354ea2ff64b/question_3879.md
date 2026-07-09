# Q3879: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `domain-separated hash`, `serialized scalar` so `eval_at_zero` reuses a transcript, hash, or domain-separation space for both `hash output` and `Lagrange coefficient`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain-separated hash`, `serialized scalar`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `hash output` and `Lagrange coefficient` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `hash output` namespace from every `Lagrange coefficient` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_zero` that feeds crafted `hash output` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
