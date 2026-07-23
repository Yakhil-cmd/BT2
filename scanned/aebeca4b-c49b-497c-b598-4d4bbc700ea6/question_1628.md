# Q1628: CheckNonce bundling and ordering conflict

## Question
Can an unprivileged attacker reach `CheckNonce` through transaction pool or bundle builder path using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `CheckNonce` reorder or co-execute conflicting intents so that later checks observe inconsistent state, causing the invariant that ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions to fail and leading to Transaction manipulation?

## Target
- File/function: blockchain/types/transaction.go:469 (CheckNonce)
- Entrypoint: transaction pool or bundle builder path
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `CheckNonce` reorder or co-execute conflicting intents so that later checks observe inconsistent state
- Invariant to test: ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions
- Expected Immunefi impact: Transaction manipulation
- Fast validation: inject conflicting bundles and standalone transactions and assert builder output cannot violate nonce or dependency ordering
