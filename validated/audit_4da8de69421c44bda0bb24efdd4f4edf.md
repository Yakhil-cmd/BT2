After thorough investigation of the codebase, I found a valid analog.

---

### Title
Failed Anchoring Transaction Receipt Processed Without Status Check, Corrupting Anchored Block State — (`File: node/sc/sub_bridge_handler.go`)

### Summary

`writeServiceChainTxReceipts` in the service-chain bridge handler processes receipts received from the parent chain without checking `receipt.Status`. When a chain-data anchoring transaction fails on the parent chain, the child chain still writes the failed receipt as a confirmed anchoring record, advances the `anchoredBlockNumber` to the failed block, and removes the transaction from the bridge tx pool — permanently suppressing any retry.

### Finding Description

`handleParentChainReceiptResponseMsg` decodes a `ServiceChainReceiptResponseMsg` P2P message and immediately delegates to `writeServiceChainTxReceipts`: [1](#0-0) 

Inside `writeServiceChainTxReceipts`, for every receipt whose tx hash is found in the bridge tx pool, the code unconditionally:

1. Calls `WriteReceiptFromParentChain` — persisting the (possibly failed) receipt as the canonical anchoring receipt for the child-chain block.
2. Calls `WriteAnchoredBlockNumber` — advancing the persistent anchored-block cursor to the block encoded in the anchoring payload.
3. Calls `RemoveTx` — evicting the transaction from the bridge tx pool, preventing any automatic retry. [2](#0-1) 

There is no guard equivalent to `if receipt.Status != types.ReceiptStatusSuccessful { continue }` anywhere in this path. The `Receipt` type carries a `Status` field that is set to a non-`ReceiptStatusSuccessful` value for every failed execution: [3](#0-2) 

### Impact Explanation

The `anchoredBlockNumber` is the persistent record that the service chain uses to track which child-chain blocks have been cryptographically committed to the parent chain. Writing it on a failed receipt means:

- The child chain permanently records a block as anchored when the parent-chain transaction that was supposed to anchor it actually reverted or ran out of gas.
- The bridge tx pool entry is removed, so the anchoring transaction is never re-submitted.
- Any downstream consumer of `ReadAnchoredBlockNumber` or `ReadReceiptFromParentChain` (e.g., cross-chain proof verification, operator dashboards, or future recovery logic) receives incorrect state.

This is persistent corruption of protected bridge state: the anchored-block cursor advances past a block that was never actually committed to the parent chain, breaking the security invariant of the service-chain anchoring mechanism.

### Likelihood Explanation

Anchoring transactions can fail on the parent chain for several non-adversarial reasons that are already documented in the codebase itself (e.g., gas price below base fee, nonce gaps). The `handleParentChainInvalidTxResponseMsg` path even has a `TODO-ServiceChain: Consider other types of tx failures` comment acknowledging unhandled failure modes. Any such failure that results in a mined-but-reverted receipt (rather than a pre-execution rejection) will silently corrupt the anchored-block state. [4](#0-3) 

### Recommendation

Add a status check at the top of the per-receipt loop in `writeServiceChainTxReceipts`:

```go
if receipt.Status != types.ReceiptStatusSuccessful {
    logger.Warn("anchoring tx failed on parent chain, skipping receipt write",
        "txHash", txHash.String(), "status", receipt.Status)
    // Do NOT remove from pool; allow retry or manual intervention.
    continue
}
```

This mirrors the correct pattern already used elsewhere in the codebase when receipt status is evaluated before acting on it. [5](#0-4) 

### Proof of Concept

1. Deploy a service chain with anchoring enabled (`--anchoring` flag).
2. Configure the parent-chain gas price to be just above the bridge operator's configured gas price so that the anchoring transaction is accepted into the mempool but reverts on execution (e.g., by temporarily raising `UpperBoundBaseFee` on the parent chain so the tx is mined but the contract call fails, or by causing a nonce collision).
3. The parent chain mines the block containing the failed anchoring tx; the receipt has `Status != ReceiptStatusSuccessful`.
4. The parent chain peer responds to the child chain's `ServiceChainReceiptRequestMsg` with this failed receipt.
5. `writeServiceChainTxReceipts` processes it: `WriteReceiptFromParentChain` stores the failed receipt, `WriteAnchoredBlockNumber` advances the cursor, `RemoveTx` drops the tx from the pool.
6. Query `kaia_getChainDataAnchoringTransaction` or read `ReadAnchoredBlockNumber` on the child chain — it reports the block as anchored despite the parent-chain transaction having failed. [2](#0-1)

### Citations

**File:** node/sc/sub_bridge_handler.go (L310-321)
```go
// handleParentChainReceiptResponseMsg handles receipt response message from parent chain.
// It will store the received receipts and remove corresponding transaction in the resending list.
func (sbh *SubBridgeHandler) handleParentChainReceiptResponseMsg(p BridgePeer, msg p2p.Msg) error {
	// TODO-Kaia-ServiceChain Need to add an option, not to write receipts.
	// Decode the retrieval message
	var receipts []*types.ReceiptForStorage
	if err := msg.Decode(&receipts); err != nil && err != rlp.EOL {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	sbh.writeServiceChainTxReceipts(sbh.subbridge.blockchain, receipts)
	return nil
}
```

**File:** node/sc/sub_bridge_handler.go (L393-407)
```go
			if invalidTx.ErrStr == blockchain.ErrGasPriceBelowBaseFee.Error() {
				logger.Info("[SC][HandleTxDropped] Request gasPrice and Magma values to parent chain")
				sbh.SyncNonceAndGasPrice()

				logger.Error("Bridge tx is removed which has lower gasPrice than UpperBoundBaseFee")
				// Remove the tx from the pool. For value transfer txs, Value Transfer Recovery
				// will retry if enabled. For anchoring txs, there is no automatic retry mechanism;
				if err := sbh.subbridge.GetBridgeTxPool().RemoveTx(tx); err != nil {
					logger.Error("Failed to remove bridge tx",
						"txType", tx.Type(), "txNonce", tx.Nonce(), "txHash", tx.Hash().String())
				} else {
					logger.Info("Removed bridge tx",
						"txType", tx.Type(), "txNonce", tx.Nonce(), "txHash", tx.Hash().String())
				}
			} // TODO-ServiceChain: Consider other types of tx failures with else {}
```

**File:** node/sc/sub_bridge_handler.go (L435-461)
```go
// writeServiceChainTxReceipts writes the received receipts of service chain transactions.
func (sbh *SubBridgeHandler) writeServiceChainTxReceipts(bc *blockchain.BlockChain, receipts []*types.ReceiptForStorage) {
	for _, receipt := range receipts {
		txHash := receipt.TxHash
		if tx := sbh.subbridge.GetBridgeTxPool().Get(txHash); tx != nil {
			if tx.Type().IsChainDataAnchoring() {
				data, err := tx.AnchoredData()
				if err != nil {
					logger.Error("failed to get anchoring data", "txHash", txHash.String(), "err", err)
					continue
				}
				decodedData, err := types.DecodeAnchoringData(data)
				if err != nil {
					logger.Warn("failed to decode anchoring tx", "txHash", txHash.String(), "err", err)
					continue
				}
				sbh.WriteReceiptFromParentChain(decodedData.GetBlockHash(), (*types.Receipt)(receipt))
				sbh.WriteAnchoredBlockNumber(decodedData.GetBlockNumber().Uint64())
			}
			// TODO-Kaia-ServiceChain: support other tx types if needed.
			sbh.subbridge.GetBridgeTxPool().RemoveTx(tx)
		} else {
			logger.Trace("received service chain transaction receipt does not exist in sentServiceChainTxs", "txHash", txHash.String())
		}
		logger.Trace("received service chain transaction receipt", "anchoring txHash", txHash.String())
	}
}
```

**File:** blockchain/types/receipt.go (L44-93)
```go
const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint(1)

	// TODO-Kaia Enable more error below.
	// Kaia specific
	// NOTE-Kaia Value should be consecutive from ReceiptStatusFailed to the last ReceiptStatusLast
	//         Add a new ReceiptStatusErrXXX before ReceiptStatusLast
	ReceiptStatusErrDefault                              = uint(0x02) // Default
	ReceiptStatusErrDepth                                = uint(0x03)
	ReceiptStatusErrContractAddressCollision             = uint(0x04)
	ReceiptStatusErrCodeStoreOutOfGas                    = uint(0x05)
	ReceiptStatuserrMaxCodeSizeExceed                    = uint(0x06)
	ReceiptStatusErrOutOfGas                             = uint(0x07)
	ReceiptStatusErrWriteProtection                      = uint(0x08)
	ReceiptStatusErrExecutionReverted                    = uint(0x09)
	ReceiptStatusErrOpcodeComputationCostLimitReached    = uint(0x0a)
	ReceiptStatusErrAddressAlreadyExists                 = uint(0x0b)
	ReceiptStatusErrNotAProgramAccount                   = uint(0x0c)
	ReceiptStatusErrNotHumanReadableAddress              = uint(0x0d)
	ReceiptStatusErrFeeRatioOutOfRange                   = uint(0x0e)
	ReceiptStatusErrAccountKeyFailNotUpdatable           = uint(0x0f)
	ReceiptStatusErrDifferentAccountKeyType              = uint(0x10)
	ReceiptStatusErrAccountKeyNilUninitializable         = uint(0x11)
	ReceiptStatusErrNotOnCurve                           = uint(0x12)
	ReceiptStatusErrZeroKeyWeight                        = uint(0x13)
	ReceiptStatusErrUnserializableKey                    = uint(0x14)
	ReceiptStatusErrDuplicatedKey                        = uint(0x15)
	ReceiptStatusErrWeightedSumOverflow                  = uint(0x16)
	ReceiptStatusErrUnsatisfiableThreshold               = uint(0x17)
	ReceiptStatusErrZeroLength                           = uint(0x18)
	ReceiptStatusErrLengthTooLong                        = uint(0x19)
	ReceiptStatusErrNestedRoleBasedKey                   = uint(0x1a)
	ReceiptStatusErrLegacyTransactionMustBeWithLegacyKey = uint(0x1b)
	ReceiptStatusErrDeprecated                           = uint(0x1c)
	ReceiptStatusErrNotSupported                         = uint(0x1d)
	ReceiptStatusErrInvalidCodeFormat                    = uint(0x1e)
	ReceiptStatusLast                                    = uint(0x1f) // Last value which is not an actual ReceiptStatus
//	ReceiptStatusErrInvalidJumpDestination   // TODO-Klaytn-Issue615
//	ReceiptStatusErrInvalidOpcode            // Default case, because no static message available
//	ReceiptStatusErrStackUnderflow           // Default case, because no static message available
//	ReceiptStatusErrStackOverflow            // Default case, because no static message available
//	ReceiptStatusErrInsufficientBalance      // No receipt available for this error
//	ReceiptStatusErrTotalTimeLimitReached    // No receipt available for this error
//	ReceiptStatusErrGasUintOverflow          // TODO-Klaytn-Issue615

)
```

**File:** datasync/chaindatafetcher/kas/repository_traces.go (L135-142)
```go
		if receipt.Status == types.ReceiptStatusSuccessful {
			internalTx, err := transformToInternalTx(trace, &offset, entryTx, true)
			if err != nil {
				logger.Error("Failed to transform tracing result into internal tx", "err", err, "txHash", common.BytesToHash(entryTx.TransactionHash).String())
				return nil, nil, err
			}
			internalTxs = append(internalTxs, internalTx...)
		}
```
