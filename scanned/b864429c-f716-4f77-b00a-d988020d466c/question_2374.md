# Q2374: Reuse child-channel state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `verify` so concurrently running sessions reuse a child-channel or waitpoint namespace for `interpolation set`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `interpolation set` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `interpolation set`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `interpolation set` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
