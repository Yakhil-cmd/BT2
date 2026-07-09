# Q2137: Bypass proof binding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and control `domain_separator`, `data` so `domain_separate_hash` accepts a `interpolation set` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/hash.rs::domain_separate_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain_separator`, `data`
- Exploit idea: Pair a proof/hash for one sender or session with a different `interpolation set` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::hash::domain_separate_hash` that feeds crafted `interpolation set` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
