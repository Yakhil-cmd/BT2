# Q1977: Equivocate per recipient

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and send recipient-specific `keygen output` variants into `reshare` so different honest parties bind different views of `derived verifying key` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Feed different `keygen output` values to different honest parties and test whether `derived verifying key` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `keygen output` / `derived verifying key` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `keygen output` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
