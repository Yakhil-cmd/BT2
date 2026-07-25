Now I have all the evidence needed. Let me trace the full exploit chain precisely.

**Key findings:**

1. `baseBridgePeer.readStatus` (bridge handshake) does NOT validate chainID — unlike `basePeer.readStatus` in `node/cn/peer.go` which explicitly checks `status.ChainID.Cmp(chainID) != 0`.

2. `SubBridge.handle` ignores the return value of `RegisterNewPeer` (line 542), so even when `RegisterNewPeer` returns an error for a wrong-chainID peer, the peer stays in `bridgePeerSet`.

3. `broadcastServiceChainReceiptRequest` iterates ALL peers with no chainID filter — unlike `broadcastServiceChainTx` which has an explicit `peer.GetChainID().Cmp(parentChainID) != 0` guard.

4. `handleParentChainReceiptResponseMsg` processes receipts from any peer without checking the sender's chainID.

---

### Title
Missing ChainID Validation in Bridge Peer Handshake and Receipt Broadcast Allows Adversarial Peer to Corrupt Anchoring State — (`node/sc/sub_bridge_handler.go`, `node/sc/bridgepeer.go`, `node/sc/subbridge.go`)

### Summary

A malicious P2P peer can connect to the SubBridge, pass the handshake (which does not validate chainID), remain registered in `bridgePeerSet` (because the `RegisterNewPeer` error is silently dropped), receive all pending bridge tx hashes via `broadcastServiceChainReceiptRequest`, and respond with forged receipts that trigger `WriteAnchoredBlockNumber`, `WriteReceiptFromParentChain`, and `RemoveTx` — permanently corrupting the bridge's anchoring state without any legitimate parent-chain confirmation.

### Finding Description

**Gap 1 — Bridge handshake does not validate chainID.**

`baseBridgePeer.readStatus` checks only `NetworkId` and `ProtocolVersion`: [1](#0-0) 

Compare to `basePeer.readStatus` in the main CN protocol, which explicitly rejects mismatched chainIDs: [2](#0-1) 

Because the bridge handshake skips this check, a peer claiming any chainID passes. The peer's `chainID` field is set from whatever the remote claims: [3](#0-2) 

**Gap 2 — `RegisterNewPeer` error is silently dropped.**

`SubBridge.handle` registers the peer in `bridgePeerSet` first, then calls `RegisterNewPeer` — but ignores its return value: [4](#0-3) 

`RegisterNewPeer` does check chainID and returns an error on mismatch: [5](#0-4) 

But because the error is not captured on line 542, the peer remains in `bridgePeerSet` and the main message loop continues.

**Gap 3 — `broadcastServiceChainReceiptRequest` sends to ALL peers with no chainID filter.** [6](#0-5) 

Contrast with `broadcastServiceChainTx`, which explicitly skips peers whose chainID does not match: [7](#0-6) 

**Gap 4 — Receipt response handler processes receipts from any peer without chainID check.** [8](#0-7) 

`writeServiceChainTxReceipts` then calls `WriteAnchoredBlockNumber`, `WriteReceiptFromParentChain`, and `RemoveTx` based solely on whether the receipt's `TxHash` matches a pending pool entry: [9](#0-8) 

### Impact Explanation

An adversarial peer that connects and sends forged receipts for pending anchoring tx hashes causes:

1. **`WriteAnchoredBlockNumber`** — persistently advances the DB-stored anchored block number to the block number embedded in the legitimate anchoring tx, making the bridge believe those blocks are anchored on the parent chain when they are not. [10](#0-9) 

2. **`WriteReceiptFromParentChain`** — writes attacker-supplied receipt data to the bridge DB under the legitimate block hash. [11](#0-10) 

3. **`RemoveTx`** — removes the pending anchoring tx from the bridge tx pool, so it will never be re-submitted to the actual parent chain. [12](#0-11) 

The combined effect is a persistent, durable corruption of the bridge's anchoring state: the bridge records blocks as anchored that were never confirmed on the parent chain, and discards the transactions that would have performed the real anchoring. This breaks the core security guarantee of the service chain's data anchoring mechanism.

### Likelihood Explanation

The SubBridge P2P port is reachable by any node that can connect to it (it is a standard P2P endpoint). The attacker only needs to:
- Know the SubBridge's P2P address (discoverable)
- Speak the `servicechain/2` protocol (public spec)
- Claim the correct `NetworkId` and `ProtocolVersion` in the handshake (no chainID check)

No privileged keys, governance access, or validator collusion is required.

### Recommendation

1. **Fix the bridge handshake**: Add a chainID check to `baseBridgePeer.readStatus`, mirroring `basePeer.readStatus`:
   ```go
   if status.ChainID.Cmp(chainID) != 0 {
       return errResp(ErrChainIDMismatch, ...)
   }
   ``` [1](#0-0) 

2. **Handle the `RegisterNewPeer` error**: In `SubBridge.handle`, capture and act on the error from `RegisterNewPeer` — either disconnect the peer or remove it from `bridgePeerSet`: [13](#0-12) 

3. **Add chainID filter to `broadcastServiceChainReceiptRequest`**: Mirror the guard already present in `broadcastServiceChainTx`: [6](#0-5) 

4. **Validate sender chainID in `handleParentChainReceiptResponseMsg`**: Check `p.GetChainID()` against the expected parent chainID before processing receipts.

### Proof of Concept

1. Start a SubBridge node with anchoring enabled.
2. Connect a malicious peer to the SubBridge P2P port, sending a valid `StatusMsg` with correct `NetworkId` and `ProtocolVersion` but a wrong `ChainID`.
3. Observe the peer is registered in `bridgePeerSet` (handshake passes, `RegisterNewPeer` error is dropped).
4. Wait for `broadcastServiceChainReceiptRequest` to fire (triggered on each local chain head event).
5. Observe the malicious peer receives the pending anchoring tx hashes.
6. Send a `ServiceChainReceiptResponseMsg` from the malicious peer containing forged receipts with those tx hashes.
7. Assert that `ReadAnchoredBlockNumber()` has been advanced and the anchoring txs have been removed from the bridge tx pool, without any actual confirmation on the parent chain.

### Citations

**File:** node/sc/bridgepeer.go (L301-301)
```go
	p.td, p.head, p.chainID = status.TD, status.CurrentBlock, status.ChainID
```

**File:** node/sc/bridgepeer.go (L305-327)
```go
func (p *baseBridgePeer) readStatus(network uint64, status *statusData) error {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if status.NetworkId != network {
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if int(status.ProtocolVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}
	return nil
}
```

**File:** node/cn/peer.go (L839-841)
```go
	if status.ChainID.Cmp(chainID) != 0 {
		return errResp(ErrChainIDMismatch, "%v (!= %v)", status.ChainID.String(), chainID.String())
	}
```

**File:** node/sc/subbridge.go (L534-542)
```go
	if err := sb.peers.Register(p); err != nil {
		// if starting node with unlock account, can't register peer until finish unlock
		p.GetP2PPeer().Log().Info("Kaia peer registration failed", "err", err)
		fmt.Println(err)
		return err
	}
	defer sb.removePeer(p.GetID())

	sb.handler.RegisterNewPeer(p)
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

**File:** node/sc/sub_bridge_handler.go (L424-428)
```go
	for _, peer := range peers {
		if peer.GetChainID().Cmp(parentChainID) != 0 {
			logger.Error("parent peer with different parent chainID", "peerID", peer.GetID(), "peer chainID", peer.GetChainID(), "parent chainID", parentChainID)
			continue
		}
```

**File:** node/sc/sub_bridge_handler.go (L436-460)
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

**File:** node/sc/sub_bridge_handler.go (L596-598)
```go
func (sbh *SubBridgeHandler) WriteReceiptFromParentChain(blockHash common.Hash, receipt *types.Receipt) {
	sbh.subbridge.chainDB.WriteReceiptFromParentChain(blockHash, receipt)
}
```
