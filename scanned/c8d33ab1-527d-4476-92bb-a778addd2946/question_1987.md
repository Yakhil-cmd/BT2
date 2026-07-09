# Q1987: Substitute app or public key

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and swap `threshold` for attacker-chosen `public key` while keeping the rest of `old_participants`, `new_participants`, `old_threshold`, `new_threshold` valid enough that `reshare` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `threshold` outputs must be bound to the exact `public key` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `threshold` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
