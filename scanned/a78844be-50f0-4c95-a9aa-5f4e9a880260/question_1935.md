# Q1935: Substitute app or public key

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and swap `derived signing share` for attacker-chosen `participant set` while keeping the rest of `participants`, `threshold` valid enough that `keygen` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `derived signing share` outputs must be bound to the exact `participant set` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived signing share` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
