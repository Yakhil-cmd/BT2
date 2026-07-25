Based on my full trace of the code, this is a valid vulnerability.

---

### Title
Unauthenticated Bridge P2P Receipt Causes Unconditional `RemoveTx` and Permanent False Anchoring State — (`node/sc/sub_bridge_handler.go`)

### Summary

`writeServiceChainTxReceipts` accepts any `ServiceChainReceiptResponseMsg` from any connected bridge P2P peer and, upon finding a matching `TxHash` in the `BridgeTxPool`, unconditionally removes the tx and writes a permanently-anchored block number — with no verification that the receipt is authentic or that the tx was ever confirmed on the parent chain.

### Finding Description

The message handler `handleParentChainReceiptResponseMsg` decodes a `[]*types.ReceiptForStorage` from any bridge P2P peer and passes it directly to `writeServiceChainTxReceipts`: [1](#0-0) 

Inside `writeServiceChainTxReceipts`, for each receipt whose `TxHash` matches a pool entry:

1. If the tx is a chain-data-anchoring tx, `WriteReceiptFromParentChain` and `WriteAnchoredBlockNumber` are called — using block hash/number decoded from the **tx's own anchored payload** (not from the receipt), so the stored anchored block number is the real child-chain block number.
2. `RemoveTx(tx)` is then called **unconditionally**, regardless of whether the receipt is authentic. [2](#0-1) 

There is no signature check, no parent-chain block inclusion proof, and no comparison of the receipt's block context against the tx's anchored data. The only guard is that `TxHash` must exist in the pool.

`WriteAnchoredBlockNumber` has a monotonic guard (only advances if the new number is greater), but that makes the corruption worse: once written, the block is permanently recorded as anchored and will never be re-anchored. [3](#0-2) 

The bridge P2P peer registration check only validates `chainID`: [4](#0-3) 

There is no cryptographic whitelist or operator-key authentication beyond the standard devp2p RLPx handshake, which any node can complete.

The code itself explicitly acknowledges there is no automatic retry for anchoring txs once removed: [5](#0-4) 

### Impact Explanation

An attacker who connects to the SubBridge P2P port with the correct `chainID` can:

1. Observe (or guess) pending anchoring tx hashes via `broadcastServiceChainReceiptRequest`, which broadcasts all pending tx hashes to all bridge peers.
2. Send a crafted `ServiceChainReceiptResponseMsg` with a `ReceiptForStorage` whose `TxHash` matches any pending anchoring tx.
3. Cause `writeServiceChainTxReceipts` to:
   - Write a fake receipt to the child-chain DB keyed by the child-chain block hash.
   - Permanently advance `AnchoredBlockNumber` to the child-chain block number embedded in the tx — marking that block as anchored even though the anchoring tx was never confirmed on the parent chain.
   - Remove the anchoring tx from `BridgeTxPool` with no retry.

The result is a **persistent false anchoring state**: the child chain permanently believes a block has been anchored to the parent chain when it has not. The anchoring tx is gone from the pool and will not be re-sent. This breaks the security guarantee of the service-chain anchoring mechanism for the targeted blocks.

### Likelihood Explanation

The bridge P2P port is a network-accessible service. The only barrier is knowing the port and having the correct `chainID` (which is public configuration). Pending tx hashes are actively broadcast to all connected bridge peers via `broadcastServiceChainReceiptRequest`. An attacker who connects as a bridge peer immediately receives these hashes and can craft the attack without any further information.

### Recommendation

Before calling `RemoveTx` and writing anchoring state, verify that the receipt is authentic:

- Cross-check the receipt against the parent chain via the `remoteBackend` (e.g., `TransactionReceipt` RPC call) before accepting it.
- Alternatively, require that the receipt's `BlockHash` and `BlockNumber` match what the parent chain reports for the given `TxHash`.
- Do not call `WriteAnchoredBlockNumber` or `RemoveTx` based solely on a P2P-delivered receipt; only do so after independent confirmation from the parent chain.

### Proof of Concept

1. Start a SubBridge node with anchoring enabled and at least one pending anchoring tx in `BridgeTxPool`.
2. Connect a malicious node to the SubBridge P2P port using the correct `chainID`.
3. Observe the pending tx hashes broadcast via `ServiceChainReceiptRequestMsg`.
4. Send a `ServiceChainReceiptResponseMsg` containing a `ReceiptForStorage` with `TxHash` set to one of the observed hashes (all other fields can be zero/empty).
5. Observe that:
   - The tx is removed from `BridgeTxPool`.
   - `ReadAnchoredBlockNumber()` returns the block number from the anchoring tx's payload.
   - The anchoring tx is never re-sent to the parent chain.
   - The parent chain has no record of the anchoring tx being confirmed.

### Citations

**File:** node/sc/sub_bridge_handler.go (L312-321)
```go
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

**File:** node/sc/sub_bridge_handler.go (L398-400)
```go
				// Remove the tx from the pool. For value transfer txs, Value Transfer Recovery
				// will retry if enabled. For anchoring txs, there is no automatic retry mechanism;
				if err := sbh.subbridge.GetBridgeTxPool().RemoveTx(tx); err != nil {
```

**File:** node/sc/sub_bridge_handler.go (L436-461)
```go
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

**File:** node/sc/sub_bridge_handler.go (L463-473)
```go
func (sbh *SubBridgeHandler) RegisterNewPeer(p BridgePeer) error {
	sbh.subbridge.addPeerCh <- struct{}{}

	if sbh.getParentChainID().Cmp(p.GetChainID()) != 0 {
		return fmt.Errorf("attempt to add a peer with different chainID failed! existing chainID: %v, new chainID: %v", sbh.getParentChainID(), p.GetChainID())
	}
	// sync nonce and gasprice with peer
	sbh.SyncNonceAndGasPrice()

	return nil
}
```

**File:** node/sc/sub_bridge_handler.go (L587-592)
```go
func (sbh *SubBridgeHandler) WriteAnchoredBlockNumber(blockNum uint64) {
	if sbh.GetLatestAnchoredBlockNumber() < blockNum {
		sbh.subbridge.chainDB.WriteAnchoredBlockNumber(blockNum)
		lastAnchoredBlockNumGauge.Update(int64(blockNum))
	}
}
```
