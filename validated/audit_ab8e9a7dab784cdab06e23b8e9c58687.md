### Title
`handleKLAYTransfer` Permanently Locks Bridged KAIA When Recipient Contract Reverts — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`BridgeTransferKLAY.sol`'s `handleKLAYTransfer` function makes an unconditional low-level call to the recipient address (`_to`) to deliver KAIA. If `_to` is a contract whose fallback reverts, the entire transaction reverts — including all state changes — and there is no admin escape hatch, no nonce-skip function, and no proxy upgrade path. The affected nonce is permanently uncompletable, the KAIA deposited on the source chain is permanently locked, and the VT recovery system loops forever on the stuck nonce.

---

### Finding Description

In `BridgeTransferKLAY.sol`, `handleKLAYTransfer` performs all state mutations (recording the nonce, updating `handleNoncesToBlockNums`, advancing `lowerHandleNonce`, emitting the event) and then makes an external call to the recipient:

```solidity
// contracts/service_chain/bridge/BridgeTransferKLAY.sol  lines 81-99
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);

emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [1](#0-0) 

Because Solidity reverts all state changes on a failed `require`, every state mutation above is rolled back when `_to.call` returns `false`. The result is:

- `handleNoncesToBlockNums[_requestedNonce]` is never durably set.
- `_updateHandleNonce` never advances `lowerHandleNonce` past the stuck nonce.
- `_setHandledRequestTxHash` is rolled back, so the nonce is not marked handled.

The nonce-advancement logic in `_updateHandleNonce` only advances `lowerHandleNonce` through a consecutive run of nonces whose `handleNoncesToBlockNums[i] > 0`:

```solidity
// BridgeTransfer.sol lines 149-155
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
``` [2](#0-1) 

Since the stuck nonce's entry is never written, `lowerHandleNonce` is permanently frozen at that nonce. The VT recovery system uses `lowerHandleNonce` (via `RecoveryBlockNumber`) as its scan start and `isHandledEvent` to skip already-handled nonces:

```go
// vt_recovery.go  line 65-70
func isHandledEvent(to *BridgeInfo, ev IRequestValueTransferEvent) bool {
    blk, err := to.bridge.HandleNoncesToBlockNums(nil, ev.GetRequestNonce())
    if err == nil && blk > 0 {
        return true
    }
    return false
}
``` [3](#0-2) 

Because `HandleNoncesToBlockNums[stuck_nonce]` is always zero, `isHandledEvent` always returns `false`, and the recovery system perpetually re-submits the same failing transaction.

There is no `skipNonce`, `forceHandle`, or owner-callable escape function in the bridge contract, and the bridge has no proxy upgrade mechanism.

---

### Impact Explanation

- **KAIA permanently locked**: The user deposited KAIA into the source-chain bridge. The destination-chain `handleKLAYTransfer` can never succeed for that nonce. The source-chain bridge holds the KAIA with no release path.
- **`lowerHandleNonce` permanently frozen**: All subsequent nonces can still be individually handled (the `_lowerHandleNonceCheck` only rejects nonces *below* `lowerHandleNonce`), but `lowerHandleNonce` itself never advances, so `recoveryBlockNumber` never advances either.
- **VT recovery DoS**: The off-chain recovery goroutine (`valueTransferRecovery.Recover`) continuously re-submits the stuck nonce, consuming operator gas and preventing the recovery system from making progress on genuinely pending transfers that share the same recovery scan window.

This satisfies the gate criterion: *"Unauthorized … burn … affecting KAIA, bridged assets, or system-managed funds"* — the KAIA is effectively burned with no on-chain recovery path.

---

### Likelihood Explanation

Any user can trigger this by calling `requestKLAYTransfer` (or the fallback) on the source bridge with `_to` set to a contract address whose fallback function reverts. This is a normal, permissionless user action. The bridge operators are then forced to relay the event exactly as emitted — they cannot alter `_to`. The condition is reachable without any privileged access.

---

### Recommendation

1. **Wrap the external call in a try-catch / success-check without reverting**: If the KAIA delivery fails, record the failure and allow the nonce to be marked as handled (e.g., credit the amount to a claimable mapping so the recipient can pull it later, or redirect to `_from`).
2. **Add an admin `skipNonce` or `forceHandleWithFallback` function** that lets the bridge owner mark a nonce as handled and redirect the KAIA to an alternative address (e.g., back to `_from` or to a recovery fund).
3. **Add a proxy/upgrade mechanism** so that stuck states can be resolved without redeploying the bridge and migrating all state.

---

### Proof of Concept

1. Deploy a malicious contract `RevertOnReceive` on the destination chain with a reverting fallback:
   ```solidity
   contract RevertOnReceive { receive() external payable { revert("no"); } }
   ```
2. On the source chain, call `requestKLAYTransfer(address(RevertOnReceive), value, "")` with `msg.value = value + fee`. The source bridge emits `RequestValueTransfer` with `to = address(RevertOnReceive)` and increments `requestNonce`.
3. Bridge operators observe the event and call `handleKLAYTransfer(..., address(RevertOnReceive), value, nonce, ...)` on the destination bridge. The call to `RevertOnReceive` reverts; the entire transaction reverts; `handleNoncesToBlockNums[nonce]` remains zero.
4. Every subsequent retry by operators or the VT recovery system produces the same revert.
5. Verify: `bridge.lowerHandleNonce()` remains at `nonce` forever; the KAIA in the source bridge is unrecoverable. [4](#0-3) [5](#0-4) [3](#0-2) [6](#0-5)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-100)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-160)
```text
    // _updateHandleNonce increases lower and upper handle nonce after the _requestedNonce is handled.
    function _updateHandleNonce(uint64 _requestedNonce) internal {
        if (_requestedNonce > upperHandleNonce) {
            upperHandleNonce = _requestedNonce;
        }

        uint64 limit = lowerHandleNonce + 200;
        if (limit > upperHandleNonce) {
            limit = upperHandleNonce;
        }

        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
    }

    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```

**File:** node/sc/vt_recovery.go (L64-71)
```go
func isHandledEvent(to *BridgeInfo, ev IRequestValueTransferEvent) bool {
	blk, err := to.bridge.HandleNoncesToBlockNums(nil, ev.GetRequestNonce())
	if err == nil && blk > 0 {
		logger.Trace("skip handled event", "nonce", ev.GetRequestNonce())
		return true
	}
	return false
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
