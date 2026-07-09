# Q3998: Mix ciphersuite domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `set_non_identity_constant` so `non` derived for one ciphersuite, proof role, or transcript label is accepted in another domain, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Create a domain or ciphersuite mix where `non` material from one role verifies in another.
- Invariant to test: Ciphersuite-specific `non` derivations must not collide across domains or protocol roles.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `non` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
