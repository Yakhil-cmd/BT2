# Q3846: Mix ciphersuite domains

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `eval_at_participant` so `interpolation set` derived for one ciphersuite, proof role, or transcript label is accepted in another domain, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Create a domain or ciphersuite mix where `interpolation set` material from one role verifies in another.
- Invariant to test: Ciphersuite-specific `interpolation set` derivations must not collide across domains or protocol roles.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `interpolation set` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
