# Q3981: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `v` so `set_non_identity_constant` reuses a transcript, hash, or domain-separation space for both `interpolation set` and `domain-separated hash`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `interpolation set` and `domain-separated hash` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `interpolation set` namespace from every `domain-separated hash` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `interpolation set` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
