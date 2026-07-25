Now I have all the code I need. Let me trace the full attack path carefully.

Based on my full trace of the code, I can now render a verdict.

**Key code path:**

`handleParentChainReceiptResponseMsg` (line 312) decodes receipts from any connected bridge peer with zero authentication beyond chain-ID matching, then calls `writeServiceChainTxReceipts`: [1](#0-0) 

`writeServiceChainTxReceipts` (line 436) uses `receipt.TxHash` (attacker-supplied) to look up the tx in the local pool. If found and it is a `ChainDataAnchoring` tx, it:
1. Decodes anchoring data **from the local tx** (not the receipt)
2. Calls `WriteAnchoredBlockNumber` with the block number from the local tx
3. Unconditionally calls `RemoveTx(tx)` [2](#0-1) 

The child chain also **broadcasts all pending anchoring tx hashes to every bridge peer** via `broadcastServiceChainReceiptRequest`, so the attacker trivially learns the target TxHash: [3](#0-2) 

`WriteAnchoredBlockNumber` has a monotonicity guard but no confirmation guard: [4](#0-3) 

---

### Title
Unauthenticated Bridge Peer Can Prematurely Remove Anchoring Txs and Corrupt Anchored Block Number via Fake `ServiceChainReceiptResponseMsg` — (`node/sc/sub_bridge_handler.go`)

### Summary
A malicious P2P bridge peer (any node that passes the chain-ID check) can send a `ServiceChainReceiptResponseMsg` containing a `ReceiptForStorage` whose `TxHash` matches a legitimate anchoring tx currently sitting in the local `bridgeTxPool`. `writeServiceChainTxReceipts` will (a) call `WriteAnchoredBlockNumber` with the block number embedded in the local tx and (b) call `RemoveTx` on that tx — all without any on-chain confirmation of the receipt.

### Finding Description
`handleParentChainReceiptResponseMsg` performs no authentication of the receipt payload beyond the peer already being connected. It decodes the `[]*types.ReceiptForStorage` slice and immediately passes it to `writeServiceChainTxReceipts`. Inside that function, the only lookup key used from the attacker-supplied receipt is `receipt.TxHash`; everything else (block number, block hash) is read from the **local** tx. Because the child chain broadcasts all pending anchoring tx hashes to every bridge peer via `broadcastServiceChainReceiptRequest`, the attacker already knows every valid TxHash to target.

### Impact Explanation
- **Premature pool removal**: The anchoring tx is evicted from `bridgeTxPool` before it is confirmed on the parent chain. `generateAndAddAnchoringTxIntoTxPool` only creates anchoring txs for blocks that are exact multiples of `chainTxPeriod`; it will not regenerate a tx for the same block. The affected child-chain blocks are permanently un-anchored.
- **Premature `WriteAnchoredBlockNumber`**: The child chain's persistent `AnchoredBlockNumber` record is advanced to reflect a block as anchored when the parent chain has no such anchoring tx. Any downstream consumer of `ReadAnchoredBlockNumber` (e.g., monitoring, cross-chain proof verification) will observe a false state.
- **Spurious `WriteReceiptFromParentChain`**: A fake receipt is written to `chainDB` keyed by the child-chain block hash, further corrupting the bridge receipt index.

This constitutes persistent corruption of protected bridge state and durable loss of the anchoring functionality for the targeted blocks.

### Likelihood Explanation
- The attacker only needs to connect as a bridge peer (chain-ID check is the sole gate).
- The child chain hands the attacker every pending anchoring TxHash via `SendServiceChainReceiptRequest`.
- Sending a single crafted P2P message is sufficient; no cryptographic material or privileged key is required.

### Recommendation
1. **Verify receipt status on-chain before acting**: Before calling `WriteAnchoredBlockNumber` or `RemoveTx`, query the local or remote backend to confirm the tx is actually included in a parent-chain block (e.g., check `receipt.Status == types.ReceiptStatusSuccessful` and that the block containing it is canonical).
2. **Authenticate the receipt source**: Only accept receipt responses from the single trusted parent-chain peer, or cross-check the receipt against a parent-chain block header obtained independently.
3. **Separate pool removal from receipt processing**: Do not remove a tx from `bridgeTxPool` until its inclusion in the parent chain is independently verified.

### Proof of Concept
1. Connect a malicious node as a bridge peer to the child-chain sub-bridge (chain-ID must match `parentChainID`).
2. Wait to receive a `ServiceChainReceiptRequestMsg`; extract any `txHash` from the list.
3. Construct a `[]*types.ReceiptForStorage` with one entry where `TxHash = <extracted hash>` and any other fields (status, block number, etc.) set arbitrarily.
4. Send this as a `ServiceChainReceiptResponseMsg` to the child-chain peer.
5. Observe: `WriteAnchoredBlockNumber` is called with the block number from the local anchoring tx, the tx is removed from `bridgeTxPool`, and `ReadAnchoredBlockNumber` now returns the prematurely advanced value — with no corresponding anchoring tx on the parent chain.

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
