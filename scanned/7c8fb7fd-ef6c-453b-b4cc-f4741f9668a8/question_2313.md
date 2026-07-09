# Q2313: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `identifiers`, `shares`, `point` so `eval_interpolation` reuses a transcript, hash, or domain-separation space for both `hash output` and `hash output`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `hash output` and `hash output` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `hash output` namespace from every `hash output` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `hash output` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
