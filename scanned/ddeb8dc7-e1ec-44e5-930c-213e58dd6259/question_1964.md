# Q1964: Reuse child-channel state

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and exploit `refresh` so concurrently running sessions reuse a child-channel or waitpoint namespace for `keygen output`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `keygen output` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `keygen output`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `keygen output` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
