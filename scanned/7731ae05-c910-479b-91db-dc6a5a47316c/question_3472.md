# Q3472: Swap participant ordering

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` with crafted `public_key` and exploit `derive_verifying_key` so participant ordering or identifier mapping for `derive` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Reorder or relabel participant-specific `derive` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `derive` / `derived signing share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
