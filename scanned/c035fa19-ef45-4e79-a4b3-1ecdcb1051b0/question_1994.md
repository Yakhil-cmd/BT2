# Q1994: Abuse normalization ambiguity

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and choose `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so `reshare` normalizes two semantically different `private share` states into one accepted output, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Construct inputs that normalize to the same accepted form while representing different semantic signer or key states.
- Invariant to test: Normalization must not collapse two distinct `private share` states into one accepted result.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `private share` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
