### Title
Unauthenticated `parentChainInfo` P2P Response Allows Bridge Nonce and Gas-Price Corruption — (`node/sc/sub_bridge_handler.go`)

### Summary

The SubBridge handler unconditionally trusts the `parentChainInfo` struct received over P2P from any connected bridge peer. Because the handshake only verifies `networkId` and `chainID` — not the identity of the legitimate MainBridge node — any peer that can connect to the SubBridge's P2P port can send a spoofed `ServiceChainParentChainInfoResponseMsg`, overwriting the bridge operator's nonce and gas-price state. This is the direct Kaia analog of the DAOFeeConfig ownership issue: a critical configuration value is read from an insufficiently-authenticated source and applied to protected bridge state.

---

### Finding Description

**Structural analog to the external report:**

| External (Solana) | Kaia analog |
|---|---|
| `DAOFeeConfig` owned by `dtfs` program | `parentChainInfo` provided by any connected bridge peer |
| `folio` reads it without ownership check | `SubBridgeHandler` reads it without peer-identity check |
| Attacker manipulates config → wrong share accounting | Attacker sends spoofed response → wrong nonce/gas-price |

**Root cause — `handleParentChainInfoResponseMsg`:**

`handleParentChainInfoResponseMsg` decodes the incoming `parentChainInfo` and directly applies it to the bridge operator account state:

```go
// node/sc/sub_bridge_handler.go:273-307
func (sbh *SubBridgeHandler) handleParentChainInfoResponseMsg(p BridgePeer, msg p2p.Msg) error {
    var pcInfo parentChainInfo
    if err := msg.Decode(&pcInfo); err != nil { ... }
    ...
    sbh.setParentOperatorNonce(pcInfo.Nonce)   // ← nonce overwritten
    sbh.setParentOperatorNonceSynced(true)      // ← bridge unblocked
    sbh.setRemoteChainValues(pcInfo)            // ← gas price overwritten
    ...
}
``` [1](#0-0) 

The corrupted nonce is then embedded directly into every subsequent anchoring transaction:

```go
// node/sc/sub_bridge_handler.go:335-336
types.TxValueKeyNonce: sbh.getParentOperatorNonce(),
types.TxValueKeyGasPrice: new(big.Int).SetUint64(sbh.remoteGasPrice),
``` [2](#0-1) 

**Why any peer can trigger this:**

The bridge peer handshake (`baseBridgePeer.readStatus`) only validates `NetworkId` and `ProtocolVersion`. There is no cryptographic check that the responding peer is the legitimate MainBridge node:

```go
// node/sc/bridgepeer.go:305-327
if status.NetworkId != network { return errResp(...) }
if int(status.ProtocolVersion) != p.version { return errResp(...) }
// ← no node-identity or address whitelist check
``` [3](#0-2) 

`SyncNonceAndGasPrice` broadcasts the info-request to **all** connected peers, and `HandleMainMsg` processes the response from **any** peer:

```go
// node/sc/sub_bridge_handler.go:567-572
func (scpm *SubBridgeHandler) SyncNonceAndGasPrice() {
    addr := scpm.GetParentOperatorAddr()
    for _, peer := range scpm.subbridge.BridgePeerSet().peers {
        peer.SendServiceChainInfoRequest(addr)
    }
}
``` [4](#0-3) 

The `parentChainInfo` struct carries the nonce, gas price, and KIP71 fee-bound configuration:

```go
// node/sc/sub_bridge_handler.go:45-50
type parentChainInfo struct {
    Nonce          uint64
    GasPrice       uint64
    KIP71Config    params.KIP71Config
    IsMagmaEnabled bool
}
``` [5](#0-4) 

---

### Impact Explanation

1. **Nonce corruption → bridge anchoring DoS and KAIA waste.** If an attacker sends `pcInfo.Nonce = math.MaxUint64 - 1`, the bridge operator's nonce is set to that value. Every subsequent anchoring transaction is signed with an impossible nonce, rejected by the parent chain, and the bridge operator's KAIA is consumed in gas fees for each failed submission. Bridge anchoring is permanently broken until an operator manually intervenes.

2. **Gas-price / KIP71Config corruption.** Setting `UpperBoundBaseFee = 0` causes `remoteGasPrice` to be set to 0 (line 191: `sbh.remoteGasPrice = pcInfo.KIP71Config.UpperBoundBaseFee`), making all bridge transactions under-priced and rejected. Setting it to `math.MaxUint64` causes the bridge operator to overpay for every transaction, draining KAIA. [6](#0-5) 

The corrupted nonce and gas price directly affect the bridge operator's KAIA balance and the liveness of cross-chain value transfer and anchoring — matching the gate criteria of "nonce consumption" and "fee charge affecting KAIA."

---

### Likelihood Explanation

- The SubBridge P2P port is reachable by any node that knows the parent chain's `chainID` and `networkId` — both are public values.
- No static-peer whitelist is enforced at the code level; `handle()` accepts any peer that passes the two-field handshake.
- The attack requires only a single spoofed P2P message after connecting; no privileged access, no key compromise, no majority-validator collusion.
- `SyncNonceAndGasPrice` is called on every new peer connection and periodically (every `SyncRequestInterval = 10` blocks), so the attacker's response will be processed promptly. [7](#0-6) 

---

### Recommendation

**Short term:** In `handleParentChainInfoResponseMsg`, verify that the responding peer's node ID matches the configured MainBridge static peer before applying the received nonce and gas-price values. Reject responses from peers whose identity has not been pre-authorized.

**Long term:** Introduce a cryptographic challenge-response during the bridge handshake so that only the legitimate MainBridge node (identified by its node key) can supply `parentChainInfo`. Alternatively, derive the parent operator nonce directly from the parent chain RPC rather than trusting a P2P peer.

---

### Proof of Concept

1. Attacker learns the SubBridge's P2P endpoint and the parent chain's `chainID` / `networkId` (both public).
2. Attacker connects to the SubBridge as a bridge peer, passing the two-field handshake.
3. The SubBridge calls `SyncNonceAndGasPrice()`, sending a `ServiceChainParentChainInfoRequestMsg` to all peers including the attacker.
4. Attacker replies with a `ServiceChainParentChainInfoResponseMsg` containing `Nonce = math.MaxUint64 - 1`.
5. `handleParentChainInfoResponseMsg` sets `pAccount.nonce = math.MaxUint64 - 1` and `nonceSynced = true`.
6. On the next block, `LocalChainHeadEvent` calls `blockAnchoringManager`, which calls `genUnsignedChainDataAnchoringTx` with `TxValueKeyNonce = math.MaxUint64 - 1`.
7. The signed transaction is submitted to the bridge tx pool and broadcast to the parent chain, where it is rejected (nonce too high). The bridge operator's KAIA is consumed in gas. Bridge anchoring is permanently stalled. [8](#0-7) [9](#0-8)

### Citations

**File:** node/sc/sub_bridge_handler.go (L35-37)
```go
const (
	SyncRequestInterval = 10
)
```

**File:** node/sc/sub_bridge_handler.go (L44-50)
```go
// parentChainInfo handles the information of parent chain, which is needed from child chain.
type parentChainInfo struct {
	Nonce          uint64
	GasPrice       uint64
	KIP71Config    params.KIP71Config
	IsMagmaEnabled bool
}
```

**File:** node/sc/sub_bridge_handler.go (L187-203)
```go
func (sbh *SubBridgeHandler) setRemoteChainValues(pcInfo parentChainInfo) {
	sbh.setRemoteGasPrice(pcInfo.GasPrice)
	if pcInfo.IsMagmaEnabled {
		// Set parent chain's gasprice with upperboundbasefee
		sbh.remoteGasPrice = pcInfo.KIP71Config.UpperBoundBaseFee
		sbh.subbridge.bridgeAccounts.SetParentKIP71Config(pcInfo.KIP71Config)
		kip71Config := sbh.subbridge.bridgeAccounts.GetParentKIP71Config()

		logger.Info("[SC][Sync] Updated parent chain values", "gasPrice", sbh.subbridge.bridgeAccounts.GetParentGasPrice(),
			"LowerBoundBaseFee", kip71Config.LowerBoundBaseFee,
			"UpperBoundBaseFee", kip71Config.UpperBoundBaseFee,
			"GasTarget", kip71Config.GasTarget,
			"MaxBlockGasUsedForBaseFee", kip71Config.MaxBlockGasUsedForBaseFee,
			"BaseFeeDenominator", kip71Config.BaseFeeDenominator)
	} else {
		logger.Info("Updated parent chain's gas price", "gasPrice", sbh.subbridge.bridgeAccounts.GetParentGasPrice())
	}
```

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

**File:** node/sc/sub_bridge_handler.go (L335-340)
```go
	values := map[types.TxValueKeyType]interface{}{
		types.TxValueKeyNonce:        sbh.getParentOperatorNonce(), // parent chain operator nonce will be increased after signing a transaction.
		types.TxValueKeyFrom:         *sbh.GetParentOperatorAddr(),
		types.TxValueKeyGasLimit:     uint64(100000), // TODO-Kaia-ServiceChain should define proper gas limit
		types.TxValueKeyGasPrice:     new(big.Int).SetUint64(sbh.remoteGasPrice),
		types.TxValueKeyAnchoredData: encodedCCTxData,
```

**File:** node/sc/sub_bridge_handler.go (L357-378)
```go
// LocalChainHeadEvent deals with servicechain feature to generate/broadcast service chain transactions and request receipts.
func (sbh *SubBridgeHandler) LocalChainHeadEvent(block *types.Block) {
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
}
```

**File:** node/sc/sub_bridge_handler.go (L527-564)
```go
func (sbh *SubBridgeHandler) generateAndAddAnchoringTxIntoTxPool(block *types.Block) error {
	if block == nil {
		return ErrInvalidBlock
	}

	// Generating Anchoring Tx
	if block.NumberU64()%sbh.chainTxPeriod != 0 {
		return nil
	}
	sbh.LockParentOperator()
	defer sbh.UnLockParentOperator()

	unsignedTx, err := sbh.genUnsignedChainDataAnchoringTx(block)
	if err != nil {
		logger.Error("Failed to generate service chain transaction", "blockNum", block.NumberU64(), "err", err)
		return err
	}
	txCount := sbh.txCount
	// Reset for the next anchoring period.
	sbh.txCount = 0
	sbh.txCountStartingBlockNumber = block.NumberU64() + 1

	signedTx, err := sbh.subbridge.bridgeAccounts.pAccount.SignTx(unsignedTx)
	if err != nil {
		logger.Error("failed signing tx", "err", err)
		return err
	}
	if err := sbh.subbridge.GetBridgeTxPool().AddLocal(signedTx); err == nil {
		sbh.addParentOperatorNonce(1)
	} else {
		logger.Debug("failed to add tx into bridge txpool", "err", err)
		return err
	}

	logger.Info("Generate an anchoring tx", "blockNum", block.NumberU64(), "blockhash", block.Hash().String(), "txCount", txCount, "txHash", signedTx.Hash().String())

	return nil
}
```

**File:** node/sc/sub_bridge_handler.go (L567-572)
```go
func (scpm *SubBridgeHandler) SyncNonceAndGasPrice() {
	addr := scpm.GetParentOperatorAddr()
	for _, peer := range scpm.subbridge.BridgePeerSet().peers {
		peer.SendServiceChainInfoRequest(addr)
	}
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
