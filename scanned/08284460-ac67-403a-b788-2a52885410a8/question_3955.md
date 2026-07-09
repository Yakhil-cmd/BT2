# Q3955: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `secret`, `degree` so `generate_polynomial` reuses a transcript, hash, or domain-separation space for both `polynomial` and `polynomial commitment`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `polynomial` and `polynomial commitment` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `polynomial` namespace from every `polynomial commitment` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `polynomial` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
