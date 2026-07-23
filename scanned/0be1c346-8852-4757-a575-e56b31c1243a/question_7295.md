# Q7295: validateAuth nonce replay window

## Question
Can an unprivileged attacker reach `validateAuth` through transaction pool admission and state transition using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and let `validateAuth` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/tx_pool.go:1087 (validateAuth)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: let `validateAuth` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
