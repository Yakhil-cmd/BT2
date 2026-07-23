# Q183: CheckNonce nonce replay window

## Question
Can an unprivileged attacker reach `CheckNonce` through transaction pool admission and state transition using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and let `CheckNonce` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/transaction.go:469 (CheckNonce)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: let `CheckNonce` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
