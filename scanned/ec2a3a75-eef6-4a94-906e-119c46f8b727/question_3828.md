# Q3828: Collide transcript domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `participant` so `eval_at_participant` reuses a transcript, hash, or domain-separation space for both `at` and `hash output`, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `at` and `hash output` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `at` namespace from every `hash output` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `at` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
