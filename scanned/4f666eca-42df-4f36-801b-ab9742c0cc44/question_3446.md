# Q3446: Swap participant ordering

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` with crafted `private_share` and exploit `derive_signing_share` so participant ordering or identifier mapping for `participant set` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Reorder or relabel participant-specific `participant set` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `participant set` / `derive` inputs, then assert whether downstream verification accepts an output that should have been rejected.
