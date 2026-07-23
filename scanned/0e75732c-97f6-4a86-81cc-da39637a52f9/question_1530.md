# Q1530: setPendingNonce bundling and ordering conflict

## Question
Can an unprivileged attacker reach `setPendingNonce` through transaction pool or bundle builder path using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `setPendingNonce` reorder or co-execute conflicting intents so that later checks observe inconsistent state, causing the invariant that ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions to fail and leading to Transaction manipulation?

## Target
- File/function: blockchain/tx_pool.go:2002 (setPendingNonce)
- Entrypoint: transaction pool or bundle builder path
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `setPendingNonce` reorder or co-execute conflicting intents so that later checks observe inconsistent state
- Invariant to test: ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions
- Expected Immunefi impact: Transaction manipulation
- Fast validation: inject conflicting bundles and standalone transactions and assert builder output cannot violate nonce or dependency ordering
