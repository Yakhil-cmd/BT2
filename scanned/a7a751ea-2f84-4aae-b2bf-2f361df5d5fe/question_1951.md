# Q1951: Equivocate per recipient

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and send recipient-specific `private share` variants into `refresh` so different honest parties bind different views of `derived verifying key` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Feed different `private share` values to different honest parties and test whether `derived verifying key` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `private share` / `derived verifying key` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `private share` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
