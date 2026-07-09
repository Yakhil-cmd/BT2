# Q3451: Bypass proof binding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and control `private_share` so `derive_signing_share` accepts a `public key` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Pair a proof/hash for one sender or session with a different `public key` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `public key` / `private share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
