The code path is confirmed. Let me trace every relevant piece before rendering the verdict.

**Code path confirmed:**
- `HandleMainMsg` (line 249) dispatches `ServiceChainParentChainInfoResponseMsg` to `handleParentChainInfoResponseMsg`
- When `poolNonce == 0` (empty `bridgeTxPool`) and `getParentOperatorNonce() <= pcInfo.Nonce`, line 302 unconditionally calls `setParentOperatorNonce(pcInfo.Nonce)` with the peer-supplied value
- No bounds check or validation on `pcInfo.Nonce` exists anywhere in the path

**Authentication boundary:**
The `Handshake` in `baseBridgePeer` only validates `NetworkId` and `ProtocolVersion` — no cryptographic proof that the peer is the legitimate parent chain node. Any peer that can reach the SubBridge P2P port and knows the `NetworkId` can connect and send `ServiceChainParentChainInfoResponseMsg`.

**`poolNonce == 0` condition:**
`GetMaxTxNonce` returns 0 when the `bridgeTxPool` is empty (startup, or after all pending txs are confirmed). This is a normal, recurring state.

**Persistence of corruption:**
After the attack, `setParentOperatorNonceSynced(true)` is called (line 304). `LocalChainHeadEvent` only calls `SyncNonceAndGasPrice()` when `nonceSynced == false`. With `nonceSynced = true`, the node never re-syncs — it keeps generating anchoring txs with nonce `math.MaxUint64`, which are permanently rejected by the parent chain txPool. The `handleParentChainInvalidTxResponseMsg` handler only auto-recovers from `ErrGasPriceBelowBaseFee`, not nonce errors.

---

### Title
Unauthenticated Bridge Peer Can Permanently Corrupt Parent Operator Nonce via Crafted `ServiceChainParentChainInfoResponseMsg` — (`node/sc/sub_bridge_handler.go`)

### Summary
Any peer that can reach the SubBridge P2P port can connect (no parent-chain identity proof required) and send a `ServiceChainParentChainInfoResponseMsg` with an attacker-controlled `Nonce`. When the `bridgeTxPool` is empty (`poolNonce == 0`), the handler unconditionally writes the peer-supplied nonce into the parent operator account, with no upper-bound validation. Setting `Nonce = math.MaxUint64` permanently halts all cross-chain anchoring and value-transfer operations.

### Finding Description
`handleParentChainInfoResponseMsg` in `node/sc/sub_bridge_handler.go` processes the `ServiceChainParentChainInfoResponseMsg` P2P message from any connected bridge peer. The logic at lines 297–302 has three branches based on `poolNonce` (the max nonce in `bridgeTxPool`): [1](#0-0) 

When `poolNonce == 0` (empty pool) and `getParentOperatorNonce() <= pcInfo.Nonce`, the `else` branch at line 302 executes `setParentOperatorNonce(pcInfo.Nonce)` with no validation of the peer-supplied value. The `else if` branch at line 297 also writes `pcInfo.Nonce` unconditionally when `getParentOperatorNonce() > pcInfo.Nonce`. In both cases, the nonce is fully attacker-controlled.

The bridge peer handshake only validates `NetworkId` and `ProtocolVersion`: [2](#0-1) 

There is no cryptographic proof that the connecting peer is the legitimate parent chain node. The SubBridge's `handle` function accepts any peer that passes this minimal check: [3](#0-2) 

After the nonce is corrupted, `setParentOperatorNonceSynced(true)` is called: [4](#0-3) 

`LocalChainHeadEvent` only triggers re-sync when `nonceSynced == false`: [5](#0-4) 

So the corrupted nonce is never automatically corrected. All subsequent anchoring transactions embed the corrupted nonce: [6](#0-5) 

### Impact Explanation
Setting `pcInfo.Nonce = math.MaxUint64` causes every subsequent `genUnsignedChainDataAnchoringTx` to produce a transaction with nonce `math.MaxUint64`. The parent chain txPool rejects these transactions permanently. `handleParentChainInvalidTxResponseMsg` only auto-recovers from `ErrGasPriceBelowBaseFee` — nonce errors have no recovery path: [7](#0-6) 

Result: **all cross-chain anchoring and value-transfer operations are permanently halted** until an operator manually intervenes to reset the nonce. This is a durable loss of core bridge functionality affecting bridged assets and cross-chain settlement.

### Likelihood Explanation
The SubBridge P2P port is a network-accessible port. The only admission check is `NetworkId` + `ProtocolVersion` — both are public knowledge for any service chain. The `poolNonce == 0` precondition is satisfied at node startup and after any period where all pending bridge txs have been confirmed, making it a regularly occurring state. An attacker with network access to the SubBridge P2P port can reliably trigger this.

### Recommendation
1. **Validate the peer-supplied nonce**: Reject any `pcInfo.Nonce` that exceeds a reasonable upper bound (e.g., current `getParentOperatorNonce() + maxAllowedDrift`).
2. **Authenticate bridge peers**: Require the connecting peer to prove it controls the expected parent chain operator address (e.g., via a signed challenge), not just match `NetworkId`/`ProtocolVersion`.
3. **Add re-sync on nonce rejection**: In `handleParentChainInvalidTxResponseMsg`, detect nonce-too-high errors and set `nonceSynced = false` to trigger automatic recovery.

### Proof of Concept
```go
// 1. Start a SubBridge node with an empty bridgeTxPool (poolNonce == 0).
// 2. Connect a malicious peer that passes the NetworkId/ProtocolVersion handshake.
// 3. Send ServiceChainParentChainInfoResponseMsg with pcInfo.Nonce = math.MaxUint64.
// 4. Assert: getParentOperatorNonce() == math.MaxUint64
// 5. Assert: genUnsignedChainDataAnchoringTx() produces a tx with nonce math.MaxUint64
// 6. Assert: parent chain txPool rejects the tx with ErrNonceTooHigh
// 7. Assert: nonceSynced remains true, no automatic recovery occurs
// 8. Assert: all subsequent anchoring attempts fail indefinitely
``` [8](#0-7)

### Citations

**File:** node/sc/sub_bridge_handler.go (L273-307)
```go
func (sbh *SubBridgeHandler) handleParentChainInfoResponseMsg(p BridgePeer, msg p2p.Msg) error {
	var pcInfo parentChainInfo
	if err := msg.Decode(&pcInfo); err != nil {
		logger.Error("failed to decode", "err", err)
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	sbh.LockParentOperator()
	defer sbh.UnLockParentOperator()

	poolNonce := sbh.subbridge.bridgeTxPool.GetMaxTxNonce(sbh.GetParentOperatorAddr())
	if poolNonce > 0 {
		poolNonce += 1
		// just check
		if sbh.getParentOperatorNonce() > poolNonce {
			logger.Error("parent chain operator nonce is bigger than the chain pool nonce.", "BridgeTxPoolNonce", poolNonce, "mainChainAccountNonce", sbh.getParentOperatorNonce())
		}
		if poolNonce < pcInfo.Nonce {
			// BridgeTxPool journal miss txs which already sent to parent-chain
			logger.Error("chain pool nonce is less than the parent chain nonce.", "chainPoolNonce", poolNonce, "receivedNonce", pcInfo.Nonce)
			sbh.setParentOperatorNonce(pcInfo.Nonce)
		} else {
			// BridgeTxPool journal has txs which don't receive receipt from parent-chain
			sbh.setParentOperatorNonce(poolNonce)
		}
	} else if sbh.getParentOperatorNonce() > pcInfo.Nonce {
		logger.Error("parent chain operator nonce is bigger than the received nonce.", "mainChainAccountNonce", sbh.getParentOperatorNonce(), "receivedNonce", pcInfo.Nonce)
		sbh.setParentOperatorNonce(pcInfo.Nonce)
	} else {
		// there is no tx in bridgetTxPool, so parent-chain's nonce is used
		sbh.setParentOperatorNonce(pcInfo.Nonce)
	}
	sbh.setParentOperatorNonceSynced(true)
	sbh.setRemoteChainValues(pcInfo)
	logger.Info("ParentChainNonceResponse", "receivedNonce", pcInfo.Nonce, "gasPrice", pcInfo.GasPrice, "mainChainAccountNonce", sbh.getParentOperatorNonce())
	return nil
```

**File:** node/sc/sub_bridge_handler.go (L335-336)
```go
	values := map[types.TxValueKeyType]interface{}{
		types.TxValueKeyNonce:        sbh.getParentOperatorNonce(), // parent chain operator nonce will be increased after signing a transaction.
```

**File:** node/sc/sub_bridge_handler.go (L359-377)
```go
	if sbh.getParentOperatorNonceSynced() {
		// TODO-Kaia if other feature use below chainTx, this condition should be refactored to use it for other feature.
		if sbh.subbridge.GetAnchoringTx() {
			sbh.blockAnchoringManager(block)
		}
		sbh.broadcastServiceChainTx()
		sbh.broadcastServiceChainReceiptRequest()

		sbh.skipSyncBlockCount = 0
	} else {
		sbh.txCountStartingBlockNumber = 0
		if sbh.skipSyncBlockCount%SyncRequestInterval == 0 {
			// TODO-Kaia too many request while sync main-net
			sbh.SyncNonceAndGasPrice()
			// check tx's receipts which parent-chain already executed in BridgeTxPool
			go sbh.broadcastServiceChainReceiptRequest()
		}
		sbh.skipSyncBlockCount++
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

**File:** node/sc/bridgepeer.go (L305-326)
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
```

**File:** node/sc/subbridge.go (L511-531)
```go
func (sb *SubBridge) handle(p BridgePeer) error {
	// Ignore maxPeers if this is a trusted peer
	if sb.peers.Len() >= sb.maxPeers && !p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
		return p2p.DiscTooManyPeers
	}
	p.GetP2PPeer().Log().Debug("Kaia peer connected", "name", p.GetP2PPeer().Name())

	// Execute the handshake
	var (
		head   = sb.blockchain.CurrentHeader()
		hash   = head.Hash()
		number = head.Number.Uint64()
		td     = sb.blockchain.GetTd(hash, number)
	)

	err := p.Handshake(sb.networkId, sb.getChainID(), td, hash)
	if err != nil {
		p.GetP2PPeer().Log().Debug("Kaia peer handshake failed", "err", err)
		fmt.Println(err)
		return err
	}
```
