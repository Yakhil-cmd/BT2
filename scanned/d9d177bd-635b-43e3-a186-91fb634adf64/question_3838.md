# Q3838: Reuse child-channel state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `eval_at_participant` so concurrently running sessions reuse a child-channel or waitpoint namespace for `serialized scalar`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `serialized scalar` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `serialized scalar`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `serialized scalar` / `at` inputs, then assert whether downstream verification accepts an output that should have been rejected.
