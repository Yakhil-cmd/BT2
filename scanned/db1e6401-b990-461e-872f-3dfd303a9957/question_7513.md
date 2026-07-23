# Q7513: newTxInternalDataEthereumBlobWithValues nonce replay window

## Question
Can an unprivileged attacker reach `newTxInternalDataEthereumBlobWithValues` through transaction pool admission and state transition using blob fields, fee caps, excess-blob-gas context, and raw transaction encoding and let `newTxInternalDataEthereumBlobWithValues` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/tx_internal_data_ethereum_blob.go:352 (newTxInternalDataEthereumBlobWithValues)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: blob fields, fee caps, excess-blob-gas context, and raw transaction encoding
- Exploit idea: let `newTxInternalDataEthereumBlobWithValues` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
