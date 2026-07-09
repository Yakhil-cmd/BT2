# Q1952: Swap participant ordering

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` with crafted `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key` and exploit `refresh` so participant ordering or identifier mapping for `threshold` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Reorder or relabel participant-specific `threshold` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `threshold` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
