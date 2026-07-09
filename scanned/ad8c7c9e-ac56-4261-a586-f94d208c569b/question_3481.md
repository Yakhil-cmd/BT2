# Q3481: Substitute app or public key

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and swap `participant set` for attacker-chosen `public key` while keeping the rest of `public_key` valid enough that `derive_verifying_key` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `participant set` outputs must be bound to the exact `public key` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `participant set` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
