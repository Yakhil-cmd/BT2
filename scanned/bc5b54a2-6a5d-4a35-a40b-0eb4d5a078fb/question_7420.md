# Q7420: SizeWithoutBlobTxSidecar nonce replay window

## Question
Can an unprivileged attacker reach `SizeWithoutBlobTxSidecar` through transaction pool admission and state transition using blob fields, fee caps, excess-blob-gas context, and raw transaction encoding and let `SizeWithoutBlobTxSidecar` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/transaction.go:679 (SizeWithoutBlobTxSidecar)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: blob fields, fee caps, excess-blob-gas context, and raw transaction encoding
- Exploit idea: let `SizeWithoutBlobTxSidecar` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
