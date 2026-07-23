# Q7714: decodePointG2 nonce replay window

## Question
Can an unprivileged attacker reach `decodePointG2` through transaction pool admission and state transition using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and let `decodePointG2` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/vm/contracts.go:1236 (decodePointG2)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: let `decodePointG2` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
