# Q2092: Reuse child-channel state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `commit` so concurrently running sessions reuse a child-channel or waitpoint namespace for `polynomial commitment`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::commit`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `polynomial commitment` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `polynomial commitment`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::commit` that feeds crafted `polynomial commitment` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
