### Title
`writeServiceChainTxReceipts` Ignores `receipt.Status`, Permanently Corrupting Anchored Block Number and Suppressing Retry — (`File: node/sc/sub_bridge_handler.go`)

---

### Summary

`writeServiceChainTxReceipts` in the service-chain sub-bridge handler processes receipts returned by the parent chain for anchoring transactions without ever inspecting `receipt.Status`. A reverted anchoring transaction is treated identically to a successful one: the child chain writes the failed receipt as a confirmed anchoring, advances the persistent `anchoredBlockNumber` state, and removes the transaction from the bridge tx pool — permanently, with no retry path.

---

### Finding Description

`SubBridgeHandler.writeServiceChainTxReceipts` (lines 436–461 of `node/sc/sub_bridge_handler.go`) is called from `handleParentChainReceiptResponseMsg` whenever the parent chain returns receipts for pending bridge transactions. For every receipt whose tx hash is found in the bridge tx pool, the function:

1. If the tx is a chain-data anchoring type, calls `WriteReceiptFromParentChain` and `WriteAnchoredBlockNumber` unconditionally.
2. Calls `RemoveTx` unconditionally — regardless of whether the on-chain execution succeeded or failed.

```go
// node/sc/sub_bridge_handler.go lines 436-461
func (sbh *SubBridgeHandler) writeServiceChainTxReceipts(bc *blockchain.BlockChain, receipts []*types.ReceiptForStorage) {
    for _, receipt := range receipts {
        txHash := receipt.TxHash
        if tx := sbh.subbridge.GetBridgeTxPool().Get(txHash); tx != nil {
            if tx.Type().IsChainDataAnchoring() {
                data, err := tx.AnchoredData()
                // ...
                sbh.WriteReceiptFromParentChain(decodedData.GetBlockHash(), (*types.Receipt)(receipt))
                sbh.WriteAnchoredBlockNumber(decodedData.GetBlockNumber().Uint64())
                // ^^^ NO receipt.Status check anywhere
            }
            sbh.subbridge.GetBridgeTxPool().RemoveTx(tx)
        }
    }
}
```

`receipt.Status` is never read. The parent chain's `handleServiceChainReceiptRequestMsg` sends receipts for any mined tx without filtering by status — so a reverted anchoring tx produces a receipt with `Status = ReceiptStatusFailed` (or another non-`ReceiptStatusSuccessful` code) that flows directly into this function.

The `handleParentChainInvalidTxResponseMsg` comment explicitly acknowledges the gap: *"For anchoring txs, there is no automatic retry mechanism"* — confirming that once `RemoveTx` is called, the anchoring is permanently abandoned.

---

### Impact Explanation

**Corrupted persistent state:** `WriteAnchoredBlockNumber` writes to the `bridgeServiceDB` under key `lastServiceChainTxReceiptKey`. After a failed anchoring tx is processed, `ReadAnchoredBlockNumber` / `GetLatestAnchoredBlockNumber` return a block number that was never actually anchored on the parent chain. This value is monotonically increasing and cannot be rolled back.

**Corrupted receipt index:** `WriteReceiptFromParentChain` stores the failed receipt keyed by the child chain block hash. `GetAnchoringTxHashByBlockNumber` (the public RPC API) reads this receipt and returns the hash of the failed tx as if it were a confirmed anchoring — misleading operators and any downstream system relying on this API for cross-chain finality.

**No retry:** The tx is removed from the bridge tx pool. The comment in `handleParentChainInvalidTxResponseMsg` confirms anchoring txs have no automatic retry mechanism. The failure is permanent and silent.

**Scope:** This meets the "persistent corruption of bridge state that breaks settlement" criterion. The anchoring mechanism is the security backbone of the service chain — it records child chain block hashes on the parent chain to provide cross-chain finality guarantees. Silent failure here means the child chain believes its state is anchored when it is not.

---

### Likelihood Explanation

Any condition that causes a `TxTypeChainDataAnchoring` or `TxTypeFeeDelegatedChainDataAnchoring` tx to be included in a parent chain block but revert triggers this path. Realistic triggers include:

- Gas price below the parent chain's base fee after a Magma fork activation (the `handleParentChainInvalidTxResponseMsg` path only handles pool-rejected txs, not mined-but-reverted ones).
- Nonce collision or operator account issues causing EVM-level failure.
- Parent chain configuration drift (e.g., fee payer not set correctly for fee-delegated anchoring txs).

The parent chain sends receipts for all mined txs without status filtering, so any such revert flows directly into `writeServiceChainTxReceipts`.

---

### Recommendation

Add a `receipt.Status` check before writing anchoring state and removing the tx from the pool:

```go
func (sbh *SubBridgeHandler) writeServiceChainTxReceipts(bc *blockchain.BlockChain, receipts []*types.ReceiptForStorage) {
    for _, receipt := range receipts {
        txHash := receipt.TxHash
        if tx := sbh.subbridge.GetBridgeTxPool().Get(txHash); tx != nil {
            if receipt.Status != types.ReceiptStatusSuccessful {
                logger.Error("service chain tx reverted on parent chain, NOT removing from pool",
                    "txHash", txHash.String(), "status", receipt.Status)
                continue // leave in pool for operator intervention / retry
            }
            if tx.Type().IsChainDataAnchoring() {
                // ... existing anchoring logic
                sbh.WriteReceiptFromParentChain(decodedData.GetBlockHash(), (*types.Receipt)(receipt))
                sbh.WriteAnchoredBlockNumber(decodedData.GetBlockNumber().Uint64())
            }
            sbh.subbridge.GetBridgeTxPool().RemoveTx(tx)
        }
    }
}
```

Emit a metric/alert on each failed receipt so operators can detect and remediate persistent anchoring failures.

---

### Proof of Concept

**Preconditions:**
- Service chain running with anchoring enabled (`AnchoringTx = true`).
- Parent chain has Magma fork active; operator's anchoring tx is broadcast with a gas price that passes pool admission but falls below the base fee at mining time (or any other condition causing EVM revert).

**Failure sequence:**

1. `generateAndAddAnchoringTxIntoTxPool` creates and signs a `TxTypeChainDataAnchoring` tx for child block N and adds it to the bridge tx pool.
2. `broadcastServiceChainTx` sends the tx to the parent chain peer.
3. The tx is mined on the parent chain but reverts (e.g., `ErrOutOfGas`, `ErrExecutionReverted`). The parent chain produces a receipt with `Status = ReceiptStatusFailed`.
4. `broadcastServiceChainReceiptRequest` requests the receipt by tx hash.
5. `handleServiceChainReceiptRequestMsg` on the parent side retrieves the receipt (no status filter) and sends it back.
6. `handleParentChainReceiptResponseMsg` → `writeServiceChainTxReceipts` receives the failed receipt. **No status check.** It calls:
   - `WriteReceiptFromParentChain(blockHash_N, failedReceipt)` — stores the failed receipt as the anchoring proof for block N.
   - `WriteAnchoredBlockNumber(N)` — advances the persistent anchored block number to N.
   - `RemoveTx(tx)` — removes the tx from the pool with no retry.
7. `GetLatestAnchoredBlockNumber()` now returns N. `GetAnchoringTxHashByBlockNumber(N)` returns the hash of the failed tx. Block N is **not** anchored on the parent chain.
8. The state divergence is permanent. No retry occurs. No error is surfaced.

**Corrupted value:** `ReadAnchoredBlockNumber()` returns N (a block number whose anchoring tx reverted), stored under `lastServiceChainTxReceiptKey` in `bridgeServiceDB`. The correct value should remain at the last successfully anchored block number. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** node/sc/sub_bridge_handler.go (L380-411)
```go
// handleParentChainInvalidTxResponseMsg receives unexecuted txs which were not executed by some of the reasons (e.g., lower gas price)
// and removes them from bridgeTxPool to prevent resending **as it is without necessary modification**
func (sbh *SubBridgeHandler) handleParentChainInvalidTxResponseMsg(msg p2p.Msg) error {
	var invalidTxs []InvalidParentChainTx
	if err := msg.Decode(&invalidTxs); err != nil && err != rlp.EOL {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	txPool := sbh.subbridge.GetBridgeTxPool()
	for _, invalidTx := range invalidTxs {
		if tx := txPool.Get(invalidTx.TxHash); tx != nil {
			logger.Error("A bridge tx was not executed", "err", invalidTx.ErrStr,
				"txHash", invalidTx.TxHash.String(),
				"txGasPrice", tx.GasPrice().Uint64())
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
		}
	}
	return nil
}
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

**File:** node/sc/sub_bridge_handler.go (L586-598)
```go
// WriteAnchoredBlockNumber writes the block number whose data has been anchored to the parent chain.
func (sbh *SubBridgeHandler) WriteAnchoredBlockNumber(blockNum uint64) {
	if sbh.GetLatestAnchoredBlockNumber() < blockNum {
		sbh.subbridge.chainDB.WriteAnchoredBlockNumber(blockNum)
		lastAnchoredBlockNumGauge.Update(int64(blockNum))
	}
}

// WriteReceiptFromParentChain writes a receipt received from parent chain to child chain
// with corresponding block hash. It assumes that a child chain has only one parent chain.
func (sbh *SubBridgeHandler) WriteReceiptFromParentChain(blockHash common.Hash, receipt *types.Receipt) {
	sbh.subbridge.chainDB.WriteReceiptFromParentChain(blockHash, receipt)
}
```

**File:** node/sc/main_bridge_handler.go (L168-200)
```go
// handleServiceChainReceiptRequestMsg handles receipt request message from child chain.
// It will find and send corresponding receipts with given transaction hashes.
func (mbh *MainBridgeHandler) handleServiceChainReceiptRequestMsg(p BridgePeer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather state data until the fetch or network limits is reached
	var (
		hash               common.Hash
		receiptsForStorage []*types.ReceiptForStorage
	)
	for len(receiptsForStorage) < downloader.MaxReceiptFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the receipt of requested service chain tx, skip if unknown.
		receipt := mbh.mainbridge.blockchain.GetReceiptByTxHash(hash)
		if receipt == nil {
			continue
		}

		receiptsForStorage = append(receiptsForStorage, (*types.ReceiptForStorage)(receipt))
	}
	if len(receiptsForStorage) == 0 {
		return nil
	}
	return p.SendServiceChainReceiptResponse(receiptsForStorage)
}
```

**File:** node/sc/api_bridge.go (L105-123)
```go
func (sb *SubBridgeAPI) GetLatestAnchoredBlockNumber() uint64 {
	return sb.subBridge.handler.GetLatestAnchoredBlockNumber()
}

func (sb *SubBridgeAPI) GetReceiptFromParentChain(blockHash common.Hash) *types.Receipt {
	return sb.subBridge.handler.GetReceiptFromParentChain(blockHash)
}

func (sb *SubBridgeAPI) GetAnchoringTxHashByBlockNumber(bn uint64) common.Hash {
	block := sb.subBridge.blockchain.GetBlockByNumber(bn)
	if block == nil {
		return common.Hash{}
	}
	receipt := sb.subBridge.handler.GetReceiptFromParentChain(block.Hash())
	if receipt == nil {
		return common.Hash{}
	}
	return receipt.TxHash
}
```

**File:** storage/database/db_manager.go (L2661-2679)
```go
// WriteAnchoredBlockNumber writes the block number whose data has been anchored to the parent chain.
func (dbm *databaseManager) WriteAnchoredBlockNumber(blockNum uint64) {
	key := lastServiceChainTxReceiptKey
	db := dbm.getDatabase(bridgeServiceDB)
	if err := db.Put(key, common.Int64ToByteBigEndian(blockNum)); err != nil {
		logger.Crit("Failed to store LatestServiceChainBlockNum", "blockNumber", blockNum, "err", err)
	}
}

// ReadAnchoredBlockNumber returns the latest block number whose data has been anchored to the parent chain.
func (dbm *databaseManager) ReadAnchoredBlockNumber() uint64 {
	key := lastServiceChainTxReceiptKey
	db := dbm.getDatabase(bridgeServiceDB)
	data, _ := db.Get(key)
	if len(data) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(data)
}
```

**File:** storage/database/db_manager.go (L2703-2716)
```go
// WriteReceiptFromParentChain writes a receipt received from parent chain to child chain
// with corresponding block hash. It assumes that a child chain has only one parent chain.
func (dbm *databaseManager) WriteReceiptFromParentChain(blockHash common.Hash, receipt *types.Receipt) {
	receiptForStorage := (*types.ReceiptForStorage)(receipt)
	db := dbm.getDatabase(bridgeServiceDB)
	byte, err := rlp.EncodeToBytes(receiptForStorage)
	if err != nil {
		logger.Crit("Failed to RLP encode receipt received from parent chain", "receipt.TxHash", receipt.TxHash, "err", err)
	}
	key := receiptFromParentChainKey(blockHash)
	if err = db.Put(key, byte); err != nil {
		logger.Crit("Failed to store receipt received from parent chain", "receipt.TxHash", receipt.TxHash, "err", err)
	}
}
```

**File:** blockchain/types/receipt.go (L44-50)
```go
const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint(1)

```
