### Title
Bridge Peer Handshake Missing Genesis Verification Allows Nonce Corruption via Unsolicited `ServiceChainParentChainInfoResponseMsg` — (File: node/sc/sub_bridge_handler.go)

### Summary

The service-chain bridge peer handshake (`baseBridgePeer.readStatus`) does not verify the parent chain's genesis hash, unlike the main-chain peer handshake (`basePeer.readStatus`). Any node that can reach the SubBridge's P2P port and claims the correct `networkId` and `chainID` (both self-reported) is admitted as a bridge peer. Once admitted, it can send an unsolicited `ServiceChainParentChainInfoResponseMsg` at any time. `handleParentChainInfoResponseMsg` unconditionally overwrites the parent operator's nonce with the attacker-supplied value and marks the nonce as synced, corrupting the bridge's nonce state and halting all subsequent bridge value transfers.

---

### Finding Description

**Step 1 — Missing genesis check in bridge handshake**

The main-chain peer handshake (`node/cn/peer.go`) rejects peers whose genesis hash does not match:

```go
if status.GenesisBlock != genesis {
    return errResp(ErrGenesisBlockMismatch, ...)
}
```

The bridge peer handshake (`node/sc/bridgepeer.go`) only checks `NetworkId` and `ProtocolVersion`:

```go
func (p *baseBridgePeer) readStatus(network uint64, status *statusData) error {
    ...
    if status.NetworkId != network {
        return errResp(ErrNetworkIdMismatch, ...)
    }
    if int(status.ProtocolVersion) != p.version {
        return errResp(ErrProtocolVersionMismatch, ...)
    }
    return nil   // ← no genesis check
}
``` [1](#0-0) [2](#0-1) 

**Step 2 — ChainID is self-reported and not cryptographically bound**

`RegisterNewPeer` rejects peers with a wrong `chainID`, but `chainID` is taken verbatim from the peer's own status message:

```go
p.td, p.head, p.chainID = status.TD, status.CurrentBlock, status.ChainID
```

An attacker simply claims the correct `chainID` in the handshake. [3](#0-2) [4](#0-3) 

**Step 3 — Unsolicited `ServiceChainParentChainInfoResponseMsg` is accepted from any peer**

`HandleMainMsg` dispatches `ServiceChainParentChainInfoResponseMsg` to `handleParentChainInfoResponseMsg` without checking whether the message was solicited or whether the sender is the legitimate parent-chain bridge:

```go
case ServiceChainParentChainInfoResponseMsg:
    if err := sbh.handleParentChainInfoResponseMsg(p, msg); err != nil {
        return err
    }
``` [5](#0-4) 

**Step 4 — Nonce is unconditionally overwritten with attacker-supplied value**

```go
func (sbh *SubBridgeHandler) handleParentChainInfoResponseMsg(p BridgePeer, msg p2p.Msg) error {
    var pcInfo parentChainInfo
    msg.Decode(&pcInfo)
    ...
    } else if sbh.getParentOperatorNonce() > pcInfo.Nonce {
        sbh.setParentOperatorNonce(pcInfo.Nonce)   // ← overwrites with attacker value
    } else {
        sbh.setParentOperatorNonce(pcInfo.Nonce)   // ← overwrites with attacker value
    }
    sbh.setParentOperatorNonceSynced(true)
    sbh.setRemoteChainValues(pcInfo)               // ← also overwrites remoteGasPrice
    ...
}
``` [6](#0-5) 

`setParentOperatorNonce` writes directly to the bridge operator account's nonce with no lower-bound guard:

```go
func (sbh *SubBridgeHandler) setParentOperatorNonce(newNonce uint64) {
    sbh.subbridge.bridgeAccounts.pAccount.SetNonce(newNonce)
}
``` [7](#0-6) 

**Step 5 — Corrupted nonce is used in all subsequent bridge transactions**

Every anchoring and value-transfer transaction is built with the corrupted nonce:

```go
values := map[types.TxValueKeyType]interface{}{
    types.TxValueKeyNonce: sbh.getParentOperatorNonce(),
    ...
}
``` [8](#0-7) 

---

### Impact Explanation

- **Nonce set too low** (below the actual on-chain nonce): every bridge transaction is rejected by the parent chain txpool with `nonce too low`. All KAIA and ERC20/ERC721 value transfers across the bridge are permanently halted until an operator manually resets the nonce.
- **Nonce set too high**: bridge transactions are queued in the parent chain txpool with a gap nonce and never executed, freezing in-flight value transfers.
- **`remoteGasPrice` / `KIP71Config` poisoned**: attacker can set `UpperBoundBaseFee` to `uint64` max, causing every bridge transaction to be built with an astronomically high gas price, draining the bridge operator's KAIA balance on each submission attempt.

The corrupted value is `bridgeAccounts.pAccount.nonce` (the parent operator nonce), which gates all bridge value-transfer and anchoring transactions.

---

### Likelihood Explanation

Any node that can reach the SubBridge's P2P listen port (default open, no IP allowlist enforced in code) and knows the public `networkId` and `chainID` (both on-chain public information) can connect. No privileged key material is required. The attacker does not need to be a validator or bridge operator. The attack can be repeated on every reconnection.

---

### Recommendation

1. **Add genesis hash verification to the bridge peer handshake**, mirroring `node/cn/peer.go`:

```go
if status.GenesisBlock != expectedGenesis {
    return errResp(ErrGenesisBlockMismatch, ...)
}
```

2. **Validate that `ServiceChainParentChainInfoResponseMsg` arrives only from the single configured parent-chain bridge peer** (e.g., check `p.GetP2PPeerID()` against a pinned node ID, analogous to SSL pinning).

3. **Apply a monotonic lower-bound guard** when updating the parent operator nonce: never allow the nonce to decrease below `max(currentNonce, poolNonce)`.

4. **Restrict inbound bridge connections** to a static allowlist of parent-chain bridge node IDs via the existing `trusted`/`static` peer mechanism.

---

### Proof of Concept

```
1. Attacker starts a node with:
   - networkId  = <SubBridge's networkId>
   - chainID    = <parent chain's chainID>  (public)
   - Any ECDSA key (RLPx identity, not checked against any allowlist)

2. Attacker dials the SubBridge's P2P port.
   - baseBridgePeer.readStatus() passes: networkId ✓, protocolVersion ✓, genesis NOT checked.
   - RegisterNewPeer() passes: chainID matches (self-reported).

3. Attacker sends ServiceChainParentChainInfoResponseMsg{Nonce: 0, GasPrice: 0}
   (no prior ServiceChainParentChainInfoRequestMsg required).

4. handleParentChainInfoResponseMsg() executes:
   - sbh.setParentOperatorNonce(0)        ← nonce corrupted to 0
   - sbh.setParentOperatorNonceSynced(true)
   - sbh.setRemoteGasPrice(0)

5. Next bridge value-transfer or anchoring tx is built with nonce=0.
   Parent chain rejects it: "nonce too low".
   Bridge halts; all pending KAIA/ERC20/ERC721 transfers are frozen.
``` [9](#0-8) [10](#0-9) [4](#0-3)

### Citations

**File:** node/sc/bridgepeer.go (L265-327)
```go
// Handshake executes the Kaia protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *baseBridgePeer) Handshake(network uint64, chainID, td *big.Int, head common.Hash) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		errc <- p2p.Send(p.rw, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
			TD:              td,
			CurrentBlock:    head,
			ChainID:         chainID,
		})
	}()
	go func() {
		e := p.readStatus(network, &status)
		if e != nil {
			errc <- e
			return
		}
		errc <- e
	}()
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for range 2 {
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-timeout.C:
			return p2p.DiscReadTimeout
		}
	}
	p.td, p.head, p.chainID = status.TD, status.CurrentBlock, status.ChainID
	return nil
}

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

**File:** node/cn/peer.go (L833-834)
```go
	if status.GenesisBlock != genesis {
		return errResp(ErrGenesisBlockMismatch, "%x (!= %x)", status.GenesisBlock[:8], genesis[:8])
```

**File:** node/sc/sub_bridge_handler.go (L114-117)
```go
// setParentOperatorNonce sets the parent chain operator nonce of parent chain operator address.
func (sbh *SubBridgeHandler) setParentOperatorNonce(newNonce uint64) {
	sbh.subbridge.bridgeAccounts.pAccount.SetNonce(newNonce)
}
```

**File:** node/sc/sub_bridge_handler.go (L249-253)
```go
	case ServiceChainParentChainInfoResponseMsg:
		logger.Debug("received ServiceChainParentChainInfoResponseMsg")
		if err := sbh.handleParentChainInfoResponseMsg(p, msg); err != nil {
			return err
		}
```

**File:** node/sc/sub_bridge_handler.go (L273-308)
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

**File:** node/sc/sub_bridge_handler.go (L463-472)
```go
func (sbh *SubBridgeHandler) RegisterNewPeer(p BridgePeer) error {
	sbh.subbridge.addPeerCh <- struct{}{}

	if sbh.getParentChainID().Cmp(p.GetChainID()) != 0 {
		return fmt.Errorf("attempt to add a peer with different chainID failed! existing chainID: %v, new chainID: %v", sbh.getParentChainID(), p.GetChainID())
	}
	// sync nonce and gasprice with peer
	sbh.SyncNonceAndGasPrice()

	return nil
```
