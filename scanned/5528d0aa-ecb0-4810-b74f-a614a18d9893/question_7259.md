# Q7259: RecoverFromMessage nonce replay window

## Question
Can an unprivileged attacker reach `RecoverFromMessage` through transaction pool admission and state transition via public `kaia_*` or `eth_*` RPC using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and let `RecoverFromMessage` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: api/api_kaia_transaction.go:636 (RecoverFromMessage)
- Entrypoint: transaction pool admission and state transition via public `kaia_*` or `eth_*` RPC
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: let `RecoverFromMessage` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
