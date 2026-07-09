# Q1990: Reuse child-channel state

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and exploit `reshare` so concurrently running sessions reuse a child-channel or waitpoint namespace for `private share`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `private share` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `private share`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `private share` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
