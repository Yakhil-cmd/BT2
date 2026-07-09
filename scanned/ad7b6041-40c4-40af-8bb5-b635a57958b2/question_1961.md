# Q1961: Substitute app or public key

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and swap `private share` for attacker-chosen `keygen output` while keeping the rest of `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key` valid enough that `refresh` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `private share` outputs must be bound to the exact `keygen output` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `private share` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
