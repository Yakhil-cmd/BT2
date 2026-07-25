### Title
Unauthenticated `ServiceChainParentChainInfoResponseMsg` Allows Any Bridge Peer to Roll Back the Parent Operator Nonce, Halting Bridge Value Transfers — (`node/sc/sub_bridge_handler.go`)

---

### Summary

The service-chain sub-bridge unconditionally trusts the `Nonce` field inside a `ServiceChainParentChainInfoResponseMsg` P2P message. Because the bridge-peer handshake omits the ChainID check that the regular Kaia peer handshake enforces, any node that shares the same `networkId` and protocol version can connect as a bridge peer and inject a crafted response. When the bridge's local tx-pool is empty (`poolNonce == 0`), the handler will set the parent-operator nonce to whatever value the peer supplies — including zero — rolling back the nonce below already-confirmed transactions and permanently stalling all subsequent bridge value-transfer and anchoring transactions.

---

### Finding Description

**Root cause — missing ChainID verification in bridge-peer handshake**

`baseBridgePeer.readStatus` (`node/sc/bridgepeer.go`) only checks `NetworkId` and `ProtocolVersion`:

```go
// node/sc/bridgepeer.go  lines 305-327
func (p *baseBridgePeer) readStatus(network uint64, status *statusData) error {
    ...
    if status.NetworkId != network {
        return errResp(ErrNetworkIdMismatch, ...)
    }
    if int(status.ProtocolVersion) != p.version {
        return errResp(ErrProtocolVersionMismatch, ...)
    }
    return nil   // ← ChainID is never verified
}
```

The regular Kaia peer handshake (`node/cn/peer.go` lines 839-840) does verify ChainID:

```go
if status.ChainID.Cmp(chainID) != 0 {
    return errResp(ErrChainIDMismatch, ...)
}
```

The bridge-peer path omits this check entirely, so any node with the correct `networkId` can complete the handshake and claim any `chainID` it likes.

**Secondary gap — `RegisterNewPeer` error is silently discarded**

`SubBridge.handle` calls `sb.handler.RegisterNewPeer(p)` but ignores the returned error:

```go
// node/sc/subbridge.go  line 542
sb.handler.RegisterNewPeer(p)   // return value discarded
```

Even if `RegisterNewPeer` detects a chainID mismatch and returns an error, the peer is already in `sb.peers` and the message loop continues, so the attacker can still send messages.

**Nonce rollback in `handleParentChainInfoResponseMsg`**

When the bridge tx-pool is empty (`poolNonce == 0`), the handler unconditionally overwrites the parent-operator nonce with the peer-supplied value — even if that value is *lower* than the current nonce:

```go
// node/sc/sub_bridge_handler.go  lines 282-303
poolNonce := sbh.subbridge.bridgeTxPool.GetMaxTxNonce(sbh.GetParentOperatorAddr())
if poolNonce > 0 {
    ...
} else if sbh.getParentOperatorNonce() > pcInfo.Nonce {
    // logs an error but still sets the nonce to the attacker-supplied value
    sbh.setParentOperatorNonce(pcInfo.Nonce)   // ← nonce decremented
} else {
    sbh.setParentOperatorNonce(pcInfo.Nonce)   // ← nonce set to attacker value
}
sbh.setParentOperatorNonceSynced(true)
sbh.setRemoteChainValues(pcInfo)
```

After the nonce is reset to zero (or any stale value), every subsequent bridge transaction is built with that stale nonce:

```go
// node/sc/sub_bridge_handler.go  line 336
types.TxValueKeyNonce: sbh.getParentOperatorNonce(),
```

The parent chain rejects these transactions (`nonce too low`), and the bridge never recovers without manual operator intervention.

---

### Impact Explanation

- All pending and future **value-transfer requests** (KAIA / ERC-20 / ERC-721) from the child chain to the parent chain are permanently stalled; assets locked in the bridge contract cannot be released.
- **Chain-data anchoring** transactions also fail, breaking the child chain's security guarantee that its state is anchored to the parent chain.
- The bridge operator nonce is a system-managed value whose corruption directly affects bridged-asset movement — matching the "nonce consumption affecting bridged assets" category of the allowed impact gate.

---

### Likelihood Explanation

- The sub-bridge listens for incoming P2P connections. Any node that knows the `networkId` and protocol version (both are public) can connect.
- The attacker does not need to wait for a `SyncNonceAndGasPrice` request; `HandleMainMsg` processes `ServiceChainParentChainInfoResponseMsg` unconditionally whenever it arrives.
- The attack is deterministic and requires no privileged keys, no majority-validator collusion, and no cryptographic breaks.
- The only practical barrier is network reachability of the sub-bridge node.

---

### Recommendation

1. **Enforce ChainID in the bridge-peer handshake** — mirror the check already present in `node/cn/peer.go`:

   ```go
   // node/sc/bridgepeer.go  readStatus
   if status.ChainID.Cmp(expectedChainID) != 0 {
       return errResp(ErrChainIDMismatch, ...)
   }
   ```

2. **Check and propagate the error from `RegisterNewPeer`** in `SubBridge.handle` so that peers with a mismatched chainID are disconnected immediately.

3. **Never decrease the parent-operator nonce** from a peer-supplied value. The nonce should only ever increase:

   ```go
   if pcInfo.Nonce > sbh.getParentOperatorNonce() {
       sbh.setParentOperatorNonce(pcInfo.Nonce)
   }
   ```

4. Consider maintaining a whitelist of authorised parent-chain peer node IDs and rejecting `ServiceChainParentChainInfoResponseMsg` from any peer not on the list.

---

### Proof of Concept

1. Attacker runs a Kaia node configured with the same `networkId` as the target service chain.
2. Attacker dials the sub-bridge node's P2P endpoint. The handshake succeeds (only `networkId` and `protocolVersion` are checked).
3. Attacker claims the correct parent `chainID` in the handshake `statusData`; `RegisterNewPeer` may log an error but the error is discarded and the peer remains connected.
4. Attacker sends a raw `ServiceChainParentChainInfoResponseMsg` with `Nonce = 0`, `GasPrice = 0`, `IsMagmaEnabled = false`.
5. `handleParentChainInfoResponseMsg` executes. With an empty bridge tx-pool (`poolNonce == 0`) and `currentNonce > 0`, the branch at line 297-299 fires and calls `setParentOperatorNonce(0)`.
6. `setParentOperatorNonceSynced(true)` is set, so `LocalChainHeadEvent` now proceeds to generate bridge transactions.
7. Every generated transaction carries `nonce = 0`; the parent chain rejects them all with `nonce too low`. The bridge is permanently stalled until an operator manually resets the nonce via `RequestParentSync` or node restart. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** node/sc/sub_bridge_handler.go (L271-308)
```go
// handleParentChainInfoResponseMsg handles parent chain info response message from parent chain.
// It will update the ParentOperatorNonce and remoteGasPrice of ServiceChainProtocolManager.
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
}
```

**File:** node/sc/sub_bridge_handler.go (L335-340)
```go
	values := map[types.TxValueKeyType]interface{}{
		types.TxValueKeyNonce:        sbh.getParentOperatorNonce(), // parent chain operator nonce will be increased after signing a transaction.
		types.TxValueKeyFrom:         *sbh.GetParentOperatorAddr(),
		types.TxValueKeyGasLimit:     uint64(100000), // TODO-Kaia-ServiceChain should define proper gas limit
		types.TxValueKeyGasPrice:     new(big.Int).SetUint64(sbh.remoteGasPrice),
		types.TxValueKeyAnchoredData: encodedCCTxData,
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

**File:** node/sc/subbridge.go (L540-543)
```go
	defer sb.removePeer(p.GetID())

	sb.handler.RegisterNewPeer(p)

```
