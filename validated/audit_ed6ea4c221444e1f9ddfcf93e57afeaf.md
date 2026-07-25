Let me check the `GetMaxTxNonce` return value when pool is empty and the sub-bridge's P2P server configuration for inbound connections.

Based on my analysis of the code, I have a clear picture of the vulnerability. Let me present my findings.

---

### Title
Unauthenticated P2P Peer Can Corrupt Parent Operator Nonce to `math.MaxUint64`, Permanently Locking Bridge Transactions — (`node/sc/sub_bridge_handler.go`)

### Summary

`handleParentChainInfoResponseMsg` unconditionally trusts the `Nonce` field from any connected bridge P2P peer. When the bridge tx pool is empty, there is no guard preventing a crafted `Nonce = math.MaxUint64` from being written directly into the parent operator's nonce. Any peer that passes the trivial bridge handshake (matching `NetworkId` + `ProtocolVersion`) can trigger this path.

### Finding Description

`SubBridgeHandler.handleParentChainInfoResponseMsg` reads a `parentChainInfo` message from a connected peer and uses its `Nonce` field to update the local parent operator nonce: [1](#0-0) 

The branching logic is:

```
poolNonce = GetMaxTxNonce(parentOperatorAddr)   // returns 0 when pool is empty
if poolNonce > 0   → use pool-based nonce
else if currentNonce > pcInfo.Nonce → use pcInfo.Nonce (corrective)
else               → setParentOperatorNonce(pcInfo.Nonce)   ← LINE 302, no validation
```

`GetMaxTxNonce` returns the sentinel value `0` when the bridge tx pool has no entries for the operator address: [2](#0-1) 

With an empty pool (`poolNonce == 0`) and the initial operator nonce of `0` (which satisfies `0 <= math.MaxUint64`), execution falls into the `else` branch and calls `setParentOperatorNonce(math.MaxUint64)` with no bounds check.

The bridge peer handshake only validates `NetworkId` and `ProtocolVersion`: [3](#0-2) 

There is no cryptographic identity check, no allowlist, and no verification that the responding peer is the same peer that received the original `ServiceChainParentChainInfoRequestMsg`. Any peer that connects to the sub-bridge's P2P port (default 50506) and matches the network/protocol version can send this message.

The sub-bridge's `handle()` accepts inbound connections from any IP unless the optional `NetRestrict` is configured: [4](#0-3) 

After the nonce is corrupted, `GenerateTransactOpts` propagates `math.MaxUint64` directly into every subsequent bridge transaction: [5](#0-4) 

### Impact Explanation

All bridge transactions (anchoring and value-transfer) built after the corruption carry nonce `math.MaxUint64`. The parent chain's tx pool rejects them as having a nonce far above the on-chain account nonce. No bridge transaction can be confirmed until the operator manually resets the nonce or a legitimate peer response arrives. If the attacker maintains the connection and continuously sends crafted responses, the `else if currentNonce > pcInfo.Nonce` self-healing branch is never reached (because `math.MaxUint64 > any_legitimate_nonce` is always true, but the attacker's next crafted response re-corrupts it before the legitimate one is processed). This durably blocks all cross-chain value transfers and anchoring, effectively locking bridged assets.

The attack also works when the pool is non-empty: if `poolNonce < math.MaxUint64` (always true for any real pool state), line 292 also sets the nonce to `pcInfo.Nonce`: [6](#0-5) 

### Likelihood Explanation

The sub-bridge P2P port is a standard TCP listener with no default IP restriction. An attacker who knows the target's `NetworkId` and `ProtocolVersion` (both are public/discoverable) can connect and send the crafted message. The attack requires no keys, no governance access, and no validator collusion — only a TCP connection to the bridge port.

### Recommendation

1. **Validate the received nonce**: Before calling `setParentOperatorNonce`, verify that `pcInfo.Nonce` does not exceed a reasonable upper bound (e.g., current operator nonce + some configurable slack, or the on-chain pending nonce queried independently).
2. **Authenticate the responding peer**: Track which peer received the `ServiceChainParentChainInfoRequestMsg` and only accept the response from that specific peer.
3. **Enforce `NetRestrict`** on the bridge P2P server by default, restricting connections to the configured parent chain node's IP.

### Proof of Concept

1. Sub-bridge starts with empty bridge tx pool; `mainChainAccountNonce = 0`.
2. Attacker connects to sub-bridge port 50506, passes handshake with matching `NetworkId` and `ProtocolVersion`.
3. Attacker sends an RLP-encoded `ServiceChainParentChainInfoResponseMsg` (`0x04`) with `parentChainInfo{Nonce: math.MaxUint64, GasPrice: 1, ...}`.
4. `handleParentChainInfoResponseMsg` executes: `poolNonce = 0`, `currentNonce (0) <= MaxUint64` → `setParentOperatorNonce(math.MaxUint64)`.
5. Sub-bridge triggers a value-transfer; `GenerateTransactOpts` returns `nonce = big.NewInt(math.MaxUint64)`.
6. Transaction is submitted to the parent chain and permanently rejected (nonce too high).
7. Attacker repeats step 3 on every `SyncNonceAndGasPrice` cycle to prevent self-healing.

### Citations

**File:** node/sc/sub_bridge_handler.go (L282-303)
```go
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
```

**File:** node/sc/bridgepool/bridge_tx_pool.go (L302-315)
```go
func (pool *BridgeTxPool) GetMaxTxNonce(from *common.Address) uint64 {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	maxNonce := uint64(0)
	if list, exist := pool.queue[*from]; exist {
		for _, t := range list.items {
			if maxNonce < t.Nonce() {
				maxNonce = t.Nonce()
			}
		}
	}
	return maxNonce
}
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

**File:** node/sc/subbridge.go (L511-543)
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

	// Register the peer locally
	if err := sb.peers.Register(p); err != nil {
		// if starting node with unlock account, can't register peer until finish unlock
		p.GetP2PPeer().Log().Info("Kaia peer registration failed", "err", err)
		fmt.Println(err)
		return err
	}
	defer sb.removePeer(p.GetID())

	sb.handler.RegisterNewPeer(p)

```

**File:** node/sc/bridge_accounts.go (L260-262)
```go
	if acc.isNonceSynced {
		nonce = new(big.Int).SetUint64(acc.nonce)
	}
```
