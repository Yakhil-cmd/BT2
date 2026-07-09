# Q3777: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `rhs` so `add` reuses a transcript, hash, or domain-separation space for both `Lagrange coefficient` and `hash output`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::add`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `rhs`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `Lagrange coefficient` and `hash output` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `Lagrange coefficient` namespace from every `hash output` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::add` that feeds crafted `Lagrange coefficient` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
