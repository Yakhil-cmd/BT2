# Q7284: FloorDataGas nonce replay window

## Question
Can an unprivileged attacker reach `FloorDataGas` through transaction pool admission and state transition using gas limit, fee cap, fee payer ratio, calldata, and transaction type bytes and let `FloorDataGas` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/state_transition.go:842 (FloorDataGas)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: gas limit, fee cap, fee payer ratio, calldata, and transaction type bytes
- Exploit idea: let `FloorDataGas` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
