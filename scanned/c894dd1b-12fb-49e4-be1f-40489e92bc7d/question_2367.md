# Q2367: Bypass proof binding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and control `public_key`, `msg_hash` so `verify` accepts a `hash output` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Pair a proof/hash for one sender or session with a different `hash output` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `hash output` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
