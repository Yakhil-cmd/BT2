# Q3471: Equivocate per recipient

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and send recipient-specific `threshold` variants into `derive_verifying_key` so different honest parties bind different views of `verifying` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Feed different `threshold` values to different honest parties and test whether `verifying` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `threshold` / `verifying` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `threshold` / `verifying` inputs, then assert whether downstream verification accepts an output that should have been rejected.
