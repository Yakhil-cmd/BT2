# Q7589: newTxInternalDataFeeDelegatedChainDataAnchoringWithRatioWithMap nonce replay window

## Question
Can an unprivileged attacker reach `newTxInternalDataFeeDelegatedChainDataAnchoringWithRatioWithMap` through transaction pool admission and state transition using gas limit, fee cap, fee payer ratio, calldata, and transaction type bytes and let `newTxInternalDataFeeDelegatedChainDataAnchoringWithRatioWithMap` accept the same economic intent twice or resurrect a replaced intent, causing the invariant that a nonce must become unspendable exactly once across pool and canonical execution to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/tx_internal_data_fee_delegated_chain_data_anchoring_with_ratio.go:80 (newTxInternalDataFeeDelegatedChainDataAnchoringWithRatioWithMap)
- Entrypoint: transaction pool admission and state transition
- Attacker controls: gas limit, fee cap, fee payer ratio, calldata, and transaction type bytes
- Exploit idea: let `newTxInternalDataFeeDelegatedChainDataAnchoringWithRatioWithMap` accept the same economic intent twice or resurrect a replaced intent
- Invariant to test: a nonce must become unspendable exactly once across pool and canonical execution
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race two raw transactions with the same logical intent and assert only one can survive from pool admission to inclusion
