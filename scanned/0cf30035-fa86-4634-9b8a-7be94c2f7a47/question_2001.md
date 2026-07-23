# Q2001: PendingBlock bundling and ordering conflict

## Question
Can an unprivileged attacker reach `PendingBlock` through transaction pool or bundle builder path using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `PendingBlock` reorder or co-execute conflicting intents so that later checks observe inconsistent state, causing the invariant that ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions to fail and leading to Transaction manipulation?

## Target
- File/function: work/work.go:202 (PendingBlock)
- Entrypoint: transaction pool or bundle builder path
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `PendingBlock` reorder or co-execute conflicting intents so that later checks observe inconsistent state
- Invariant to test: ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions
- Expected Immunefi impact: Transaction manipulation
- Fast validation: inject conflicting bundles and standalone transactions and assert builder output cannot violate nonce or dependency ordering
