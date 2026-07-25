### Title
`doSubscribeBridge` Does Not Verify On-Chain `counterpartBridge` Consistency, Enabling Mismatched Bridge Pair Activation That Misdirects Value Transfers — (`node/sc/api_bridge.go`)

---

### Summary

`doSubscribeBridge` activates event subscriptions for a child/parent bridge pair without verifying that each bridge contract's on-chain `counterpartBridge` field actually points to the other bridge. If an operator accidentally subscribes a mismatched pair, the bridge manager will process value-transfer events from the child bridge and attempt to handle them against the wrong parent bridge, causing bridged assets to be permanently stuck or incorrectly minted on the parent chain.

---

### Finding Description

`doSubscribeBridge` calls `IsValidBridgePair`, which only checks the bridge manager's **in-memory** counterpart-address mapping — it never reads the on-chain `counterpartBridge` state:

```go
// node/sc/api_bridge.go  doSubscribeBridge
func (sb *SubBridgeAPI) doSubscribeBridge(cBridgeAddr, pBridgeAddr common.Address) error {
    if !sb.subBridge.bridgeManager.IsValidBridgePair(cBridgeAddr, pBridgeAddr) {
        return ErrInvalidBridgePair
    }
    // ... subscribes events, adds recovery — no on-chain counterpart check
}
``` [1](#0-0) 

`IsValidBridgePair` only validates the in-memory state set during `doRegisterBridge`:

```go
func (bm *BridgeManager) IsValidBridgePair(bridge1, bridge2 common.Address) bool {
    b1, ok1 := bm.GetBridgeInfo(bridge1)
    b2, ok2 := bm.GetBridgeInfo(bridge2)
    if !ok1 || !ok2 { return false }
    return bridge1 == b2.counterpartAddress && bridge2 == b1.counterpartAddress
}
``` [2](#0-1) 

The on-chain `counterpartBridge` field is set **separately** via `setCounterPartBridge()` after `RegisterBridge` is called:

```solidity
function setCounterPartBridge(address _bridge) external onlyOwner {
    counterpartBridge = _bridge;
    emit CounterpartBridgeChanged(_bridge);
}
``` [3](#0-2) 

The bridge manager **uses** the registered counterpart bridge object to look up counterpart token addresses during value-transfer handling:

```go
ctTokenAddr, err := bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)
``` [4](#0-3) 

The Go binding for `CounterpartBridge()` is available and callable at zero cost:

```go
func (_Bridge *BridgeCaller) CounterpartBridge(opts *bind.CallOpts) (common.Address, error) {
    ...
}
``` [5](#0-4) 

Because `doSubscribeBridge` never calls this getter, an operator who accidentally calls `RegisterBridge(cBridgeA, pBridgeB)` when `cBridgeA.counterpartBridge == pBridgeA` will activate a subscription that routes all of `cBridgeA`'s value-transfer events to `pBridgeB`.

---

### Impact Explanation

**Scenario A — stuck bridged assets (lock/unlock mode):**
1. User deposits ERC-20 tokens into `cBridgeA`; tokens are locked there.
2. Bridge manager queries `pBridgeB.RegisteredTokens(tokenAddr)` — returns zero address because `pBridgeB` does not know this token.
3. `handleRequestValueTransferEvent` returns an error; the pending event is retried indefinitely.
4. User's tokens are permanently locked in `cBridgeA` with no release path.

**Scenario B — unauthorized mint of bridged assets (mint/burn mode):**
1. Same deposit into `cBridgeA`.
2. `pBridgeB` happens to have the same token registered and the bridge manager's account is an operator on `pBridgeB`.
3. `HandleERC20Transfer` succeeds on `pBridgeB`, minting tokens to the recipient on the parent chain.
4. `pBridgeA` (the correct counterpart) never processes these events; its nonce tracking is never updated.
5. Tokens are minted on the parent chain without proper backing, constituting unauthorized minting of bridged assets. [6](#0-5) 

---

### Likelihood Explanation

The trigger is the same class as M-04: a semi-trusted operator (the sub-bridge node operator) makes a pairing mistake. The risk increases proportionally with the number of bridge pairs managed simultaneously — exactly the scenario the original report identified as the realistic failure mode. The code has the on-chain getter available but does not call it, so the mistake is entirely preventable at the code level.

---

### Recommendation

Add an on-chain consistency check inside `doSubscribeBridge` (after `IsValidBridgePair` passes, before subscribing events):

```go
cBi, _ := sb.subBridge.bridgeManager.GetBridgeInfo(cBridgeAddr)
pBi, _ := sb.subBridge.bridgeManager.GetBridgeInfo(pBridgeAddr)

cOnChainCP, err := cBi.bridge.CounterpartBridge(nil)
if err != nil || cOnChainCP != pBridgeAddr {
    return errors.New("child bridge on-chain counterpartBridge does not match registered parent bridge")
}
pOnChainCP, err := pBi.bridge.CounterpartBridge(nil)
if err != nil || pOnChainCP != cBridgeAddr {
    return errors.New("parent bridge on-chain counterpartBridge does not match registered child bridge")
}
```

This mirrors the M-04 mitigation (`require(_baseToken == _newStrategy.getBaseToken())`) exactly: read the on-chain compatibility field and reject the operation if it does not match the intended pairing.

---

### Proof of Concept

1. Deploy two independent bridge pairs: `(cBridgeA, pBridgeA)` and `(cBridgeB, pBridgeB)`.
2. Call `cBridgeA.setCounterPartBridge(pBridgeA)` and `pBridgeA.setCounterPartBridge(cBridgeA)`.
3. Operator accidentally calls `subbridge_registerBridge(cBridgeA, pBridgeB)` — succeeds with no error.
4. Operator calls `subbridge_subscribeBridge(cBridgeA, pBridgeB)` — `IsValidBridgePair` passes (in-memory state is consistent), subscription is activated.
5. User calls `requestERC20Transfer` on `cBridgeA`; tokens are locked there.
6. Bridge manager calls `pBridgeB.RegisteredTokens(tokenAddr)` → returns `address(0)`.
7. `handleRequestValueTransferEvent` returns `"can't get counterpart token from bridge"` and the nonce is never handled.
8. User's tokens are permanently locked in `cBridgeA`. [7](#0-6) [8](#0-7)

### Citations

**File:** node/sc/api_bridge.go (L175-206)
```go
func (sb *SubBridgeAPI) doSubscribeBridge(cBridgeAddr, pBridgeAddr common.Address) error {
	if !sb.subBridge.bridgeManager.IsValidBridgePair(cBridgeAddr, pBridgeAddr) {
		return ErrInvalidBridgePair
	}

	err := sb.subBridge.bridgeManager.SubscribeEvent(cBridgeAddr)
	if err != nil {
		logger.Error("Failed to SubscribeEvent child bridge", "addr", cBridgeAddr, "err", err)
		return err
	}

	err = sb.subBridge.bridgeManager.SubscribeEvent(pBridgeAddr)
	if err != nil {
		logger.Error("Failed to SubscribeEvent parent bridge", "addr", pBridgeAddr, "err", err)
		sb.subBridge.bridgeManager.UnsubscribeEvent(cBridgeAddr)
		return err
	}

	sb.subBridge.bridgeManager.journal.cacheMu.Lock()
	sb.subBridge.bridgeManager.journal.cache[cBridgeAddr].Subscribed = true
	sb.subBridge.bridgeManager.journal.cacheMu.Unlock()

	// Update the journal's subscribed flag.
	sb.subBridge.bridgeManager.journal.rotate(sb.subBridge.bridgeManager.GetAllBridge())

	err = sb.subBridge.bridgeManager.AddRecovery(cBridgeAddr, pBridgeAddr)
	if err != nil {
		sb.subBridge.bridgeManager.UnsubscribeEvent(cBridgeAddr)
		sb.subBridge.bridgeManager.UnsubscribeEvent(pBridgeAddr)
		return err
	}
	return nil
```

**File:** node/sc/api_bridge.go (L316-345)
```go
func (sb *SubBridgeAPI) doRegisterBridge(cBridgeAddr common.Address, pBridgeAddr common.Address) error {
	cBridge, err := bridge.NewBridge(cBridgeAddr, sb.subBridge.localBackend)
	if err != nil {
		return err
	}
	pBridge, err := bridge.NewBridge(pBridgeAddr, sb.subBridge.remoteBackend)
	if err != nil {
		return err
	}

	bm := sb.subBridge.bridgeManager
	err = bm.SetBridgeInfo(cBridgeAddr, cBridge, pBridgeAddr, pBridge, sb.subBridge.bridgeAccounts.cAccount, true, false)
	if err != nil {
		return err
	}
	err = bm.SetBridgeInfo(pBridgeAddr, pBridge, cBridgeAddr, cBridge, sb.subBridge.bridgeAccounts.pAccount, false, false)
	if err != nil {
		bm.DeleteBridgeInfo(cBridgeAddr)
		return err
	}
	return nil
}

func (sb *SubBridgeAPI) RegisterBridge(cBridgeAddr, pBridgeAddr common.Address, bridgeAliasP *string) error {
	bridgeAlias := stringDeref(bridgeAliasP)
	if err := sb.subBridge.bridgeManager.SetJournal(bridgeAlias, cBridgeAddr, pBridgeAddr); err != nil {
		return err
	}
	return sb.doRegisterBridge(cBridgeAddr, pBridgeAddr)
}
```

**File:** node/sc/bridge_manager.go (L292-360)
```go
// handleRequestValueTransferEvent handles the given request value transfer event.
func (bi *BridgeInfo) handleRequestValueTransferEvent(ev IRequestValueTransferEvent) error {
	var (
		tokenType                         = ev.GetTokenType()
		tokenAddr, from, to, contractAddr = ev.GetTokenAddress(), ev.GetFrom(), ev.GetTo(), ev.GetRaw().Address
		txHash                            = ev.GetRaw().TxHash
		valueOrTokenId                    = ev.GetValueOrTokenId()
		requestNonce, blkNumber           = ev.GetRequestNonce(), ev.GetRaw().BlockNumber
		extraData                         = ev.GetExtraData()
	)

	ctpartTokenAddr := bi.GetCounterPartToken(tokenAddr)
	// TODO-Kaia-Servicechain Add counterpart token address in requestValueTransferEvent
	if tokenType != KAIA && ctpartTokenAddr == (common.Address{}) {
		logger.Warn("Unregistered counter part token address.", "addr", ctpartTokenAddr.Hex())
		ctTokenAddr, err := bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)
		if err != nil {
			return err
		}
		if ctTokenAddr == (common.Address{}) {
			return errors.New("can't get counterpart token from bridge")
		}
		if err := bi.RegisterToken(tokenAddr, ctTokenAddr); err != nil {
			return err
		}
		ctpartTokenAddr = ctTokenAddr
		logger.Info("Register counter part token address.", "addr", ctpartTokenAddr.Hex(), "cpAddr", ctTokenAddr.Hex())
	}

	bridgeAcc := bi.account

	bridgeAcc.Lock()
	defer bridgeAcc.UnLock()

	auth := bridgeAcc.GenerateTransactOpts()

	var handleTx *types.Transaction
	var err error

	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}

	bridgeAcc.IncNonce()

	bi.bridgeDB.WriteHandleTxHashFromRequestTxHash(txHash, handleTx.Hash())
	return nil
}
```

**File:** node/sc/bridge_manager.go (L545-552)
```go
func (bm *BridgeManager) IsValidBridgePair(bridge1, bridge2 common.Address) bool {
	b1, ok1 := bm.GetBridgeInfo(bridge1)
	b2, ok2 := bm.GetBridgeInfo(bridge2)
	if !ok1 || !ok2 {
		return false
	}
	return bridge1 == b2.counterpartAddress && bridge2 == b1.counterpartAddress
}
```

**File:** contracts/service_chain/bridge/BridgeCounterPart.sol (L27-33)
```text
    function setCounterPartBridge(address _bridge)
        external
        onlyOwner
    {
        counterpartBridge = _bridge;
        emit CounterpartBridgeChanged(_bridge);
    }
```

**File:** contracts/bindings/bridge/bridge.go (L571-582)
```go
func (_Bridge *BridgeCaller) CounterpartBridge(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Bridge.contract.Call(opts, &out, "counterpartBridge")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

```
