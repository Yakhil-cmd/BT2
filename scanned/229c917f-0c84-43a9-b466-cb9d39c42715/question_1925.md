# Q1925: Equivocate per recipient

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and send recipient-specific `derived signing share` variants into `keygen` so different honest parties bind different views of `derived verifying key` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Feed different `derived signing share` values to different honest parties and test whether `derived verifying key` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `derived signing share` / `derived verifying key` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived signing share` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
