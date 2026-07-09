# Q1983: Bypass proof binding

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and control `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so `reshare` accepts a `participant set` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Pair a proof/hash for one sender or session with a different `participant set` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `participant set` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
