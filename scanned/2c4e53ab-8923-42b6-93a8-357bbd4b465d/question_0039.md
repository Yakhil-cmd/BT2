# Q39: nonce nonce replay window

## Question
Can an unprivileged attacker reach `nonce` through transaction pool admission and state transition via public `kaia_*` or `eth_*` RPC using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and let `nonce` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: api/tx_args.go:390 (nonce)
- Entrypoint: transaction pool admission and state transition via public `kaia_*` or `eth_*` RPC
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: let `nonce` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
