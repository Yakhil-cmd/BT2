# Q2450: Reuse child-channel state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `prove_with_nonce` so concurrently running sessions reuse a child-channel or waitpoint namespace for `transcript state`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `transcript state` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `transcript state`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `transcript state` / `forked transcript` inputs, then assert whether downstream verification accepts an output that should have been rejected.
