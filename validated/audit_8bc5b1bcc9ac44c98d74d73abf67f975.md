Let me read the key files more carefully to confirm the full attack path and any guards I might have missed.

The code path is fully confirmed. Here is the complete analysis:

---

### Title
Unauthenticated Bridge P2P Receipt Response Corrupts `latestAnchoredBlockNumber` and Permanently Drops Anchoring Tx — (`node/sc/sub_bridge_handler.go`)

### Summary
A malicious node that connects as a bridge P2P peer to the sub-bridge can send an unsolicited `ServiceChainReceiptResponseMsg` containing a `ReceiptForStorage` whose `TxHash` matches any pending anchoring transaction in the `BridgeTxPool`. The sub-bridge processes this without any on-chain verification or receipt status check, advancing `latestAnchoredBlockNumber` and permanently removing the anchoring tx from the pool, causing the bridge to believe anchoring succeeded for a block that was never actually anchored on the parent chain.

### Finding Description

**Step 1 — Entry point (no authentication).**
`HandleMainMsg` dispatches `ServiceChainReceiptResponseMsg` directly to `handleParentChainReceiptResponseMsg` with no per-message authentication beyond the P2P connection itself: [1](#0-0) 

`handleParentChainReceiptResponseMsg` decodes the peer-supplied receipts and immediately calls `writeServiceChainTxReceipts` with no further checks: [2](#0-1) 

**Step 2 — TxHash lookup drives all downstream state mutations.**
`writeServiceChainTxReceipts` uses `receipt.TxHash` (attacker-controlled) to look up the tx in the `BridgeTxPool`. If found, it decodes the anchoring data from the *local* tx (not the receipt), then unconditionally calls `WriteAnchoredBlockNumber` and `RemoveTx`. There is **no check on `receipt.Status`**: [3](#0-2) 

**Step 3 — `WriteAnchoredBlockNumber` persists the corrupted value.**
The only guard is a monotonicity check (only writes if new value > current). A fake receipt for the highest pending anchoring tx advances the stored value permanently: [4](#0-3) 

**Step 4 — Attacker learns the TxHash trivially.**
The sub-bridge broadcasts all pending anchoring tx hashes to every connected bridge peer on every new local block via `broadcastServiceChainReceiptRequest`: [5](#0-4) 

**Step 5 — Bridge peer admission is chainID-only.**
`RegisterNewPeer` rejects peers with a mismatched chainID but otherwise admits any node, making the attacker's entry point permissionless for anyone running a parent-chain node: [6](#0-5) 

### Impact Explanation

After the attack:
- `latestAnchoredBlockNumber` is advanced to the block number embedded in the legitimate local anchoring tx, even though that tx was never included on the parent chain.
- The anchoring tx is removed from `BridgeTxPool` and will never be re-submitted (there is no automatic retry for anchoring txs, as noted in the code comment at line 399).
- The sub-bridge permanently loses the anchoring record for that child-chain block. The parent chain never receives the anchored block data, breaking the settlement guarantee of the service chain.

This is a durable, irreversible corruption of the anchoring state — a core service-chain function — triggered by a single unauthenticated P2P message.

### Likelihood Explanation

- Any node running on the parent chain can connect as a bridge peer (chainID check only).
- The pending tx hashes are broadcast to all connected bridge peers on every block, so the attacker learns the target hash passively.
- The attack requires sending a single crafted P2P message; no cryptographic material, no privileged keys, no majority collusion.

### Recommendation

1. **Verify receipt on-chain before trusting it.** In `writeServiceChainTxReceipts`, cross-check the receipt against the parent chain's canonical state (e.g., call `blockchain.GetReceiptByTxHash(txHash)` on the local parent-chain view, or require the receipt to include a block hash that can be verified against a known parent-chain header).
2. **Check `receipt.Status`.** Reject receipts with `Status != ReceiptStatusSuccessful` before advancing `latestAnchoredBlockNumber` or removing the tx.
3. **Correlate responses to requests.** Track which hashes were requested from which peer and ignore unsolicited or mismatched responses.
4. **Authenticate bridge peers more strictly.** Consider requiring bridge peers to prove they are the configured parent-chain operator node rather than accepting any chainID-matching peer.

### Proof of Concept

```
1. Attacker runs a node on the parent chain with the correct chainID.
2. Attacker connects as a bridge peer to the sub-bridge.
3. Sub-bridge broadcasts pending anchoring tx hashes via broadcastServiceChainReceiptRequest.
4. Attacker captures hash H of a pending anchoring tx.
5. Attacker sends ServiceChainReceiptResponseMsg containing a ReceiptForStorage{TxHash: H, Status: 1}.
6. handleParentChainReceiptResponseMsg → writeServiceChainTxReceipts:
   - Finds the real tx in BridgeTxPool by H.
   - Decodes anchoring data from the local tx (block number N).
   - Calls WriteAnchoredBlockNumber(N) → persists N to DB.
   - Calls RemoveTx(tx) → tx is gone from the pool.
7. Assert: ReadAnchoredBlockNumber() == N, BridgeTxPool.Get(H) == nil.
8. The anchoring tx for block N is never submitted to the parent chain.
   The bridge permanently believes block N was anchored.
```

### Citations

**File:** node/sc/sub_bridge_handler.go (L255-259)
```go
	case ServiceChainReceiptResponseMsg:
		logger.Debug("received ServiceChainReceiptResponseMsg")
		if err := sbh.handleParentChainReceiptResponseMsg(p, msg); err != nil {
			return err
		}
```

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

**File:** node/sc/sub_bridge_handler.go (L476-482)
```go
func (sbh *SubBridgeHandler) broadcastServiceChainReceiptRequest() {
	hashes := sbh.subbridge.GetBridgeTxPool().PendingTxHashesByAddress(sbh.GetParentOperatorAddr(), int(sbh.GetSentChainTxsLimit())) // TODO-Kaia-Servicechain change GetSentChainTxsLimit type to int from uint64
	for _, peer := range sbh.subbridge.BridgePeerSet().peers {
		peer.SendServiceChainReceiptRequest(hashes)
		logger.Debug("sent ServiceChainReceiptRequest", "peerID", peer.GetID(), "numReceiptsRequested", len(hashes))
	}
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
