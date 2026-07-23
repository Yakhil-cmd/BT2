# Q8890: SenderPubkey bundling and ordering conflict

## Question
Can an unprivileged attacker reach `SenderPubkey` through transaction pool or bundle builder path using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `SenderPubkey` reorder or co-execute conflicting intents so that later checks observe inconsistent state, causing the invariant that ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions to fail and leading to Transaction manipulation?

## Target
- File/function: blockchain/types/transaction_signing.go:214 (SenderPubkey)
- Entrypoint: transaction pool or bundle builder path
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `SenderPubkey` reorder or co-execute conflicting intents so that later checks observe inconsistent state
- Invariant to test: ordering-sensitive execution must preserve nonce monotonicity and dependency assumptions
- Expected Immunefi impact: Transaction manipulation
- Fast validation: inject conflicting bundles and standalone transactions and assert builder output cannot violate nonce or dependency ordering
