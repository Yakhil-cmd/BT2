# Q7265: setGas nonce replay window

## Question
Can an unprivileged attacker reach `setGas` through transaction pool admission and state transition via public `kaia_*` or `eth_*` RPC using gas limit, fee cap, fee payer ratio, calldata, and transaction type bytes and let `setGas` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: api/tx_args.go:394 (setGas)
- Entrypoint: transaction pool admission and state transition via public `kaia_*` or `eth_*` RPC
- Attacker controls: gas limit, fee cap, fee payer ratio, calldata, and transaction type bytes
- Exploit idea: let `setGas` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
