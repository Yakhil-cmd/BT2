### Title
Bridge Event Handler Processes Re-org'd (Removed) `RequestValueTransfer` Logs Without Checking `log.Removed`, Causing Unauthorized Asset Transfer and Permanently Stuck Funds — (`node/sc/sub_event_handler.go`, `node/sc/bridge_manager.go`)

---

### Summary

The Kaia service-chain bridge operator processes `RequestValueTransfer` and `RequestValueTransferEncoded` events without checking whether the underlying log has been marked `Removed=true` by a chain re-org. When a re-org occurs on the source chain, the subscription delivers the old log with `Removed=true` followed by the new canonical log with `Removed=false`. Because neither `ProcessRequestEvent` nor `AddRequestValueTransferEvents` inspects `ev.GetRaw().Removed`, the operator submits a `handleKLAYTransfer` / `handleERC20Transfer` call to the destination bridge based on the now-invalid (removed) transaction hash. The destination bridge executes the transfer and permanently closes the vote for that `requestNonce`. When the canonical event (different `txHash`, same `requestNonce`) is subsequently processed, `_voteValueTransfer` returns `false` (vote already closed) and the function exits silently. The user's assets locked in the source bridge by the canonical transaction are permanently irrecoverable.

---

### Finding Description

**Source-chain event subscription — no `Removed` check**

`ProcessRequestEvent` in `sub_event_handler.go` unconditionally forwards every received event to `AddRequestValueTransferEvents`:

```go
// node/sc/sub_event_handler.go L71-86
func (cce *ChildChainEventHandler) ProcessRequestEvent(ev IRequestValueTransferEvent) error {
    ...
    handleBridgeInfo.AddRequestValueTransferEvents([]IRequestValueTransferEvent{ev})
    return nil
}
```

`AddRequestValueTransferEvents` in `bridge_manager.go` also performs no `Removed` check:

```go
// node/sc/bridge_manager.go L402-425
func (bi *BridgeInfo) AddRequestValueTransferEvents(evs []IRequestValueTransferEvent) {
    for _, ev := range evs {
        ...
        bi.pendingRequestEvent.Put(ev)
        ...
    }
}
```

The `BridgeRequestValueTransfer` struct carries `Raw types.Log`, which contains the `Removed bool` field set by the Kaia subscription layer during a re-org. Neither call site reads it.

**Destination bridge — nonce closed after first handle**

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` closes the vote for a `requestNonce` on first execution:

```solidity
// contracts/service_chain/bridge/BridgeTransferKLAY.sol L75-99
_lowerHandleNonceCheck(_requestedNonce);
if (!_voteValueTransfer(_requestedNonce)) { return; }
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);
...
(bool ok, ) = _to.call.value(_value)("");
```

Once the vote for nonce N is closed, any subsequent call with the same nonce returns early at `_voteValueTransfer`. If `lowerHandleNonce` has advanced past N (via `_updateHandleNonce`), `_lowerHandleNonceCheck` reverts with `"removed vote"`.

**`_updateHandleNonce` deletes vote records, destroying recovery path**

```solidity
// contracts/service_chain/bridge/BridgeTransfer.sol L149-155
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
```

After `lowerHandleNonce` advances past nonce N, `handleNoncesToBlockNums[N]` = 0, so `isHandledEvent` in the VTR returns `false` and VTR re-queues the canonical event — but `_lowerHandleNonceCheck` then reverts it permanently.

---

### Impact Explanation

**Unauthorized asset transfer**: The destination bridge sends KLAY/ERC20 to the recipient based on a removed (no-longer-canonical) transaction. The source-chain state for that transaction was rolled back by the re-org; the bridge's liquidity is drained without a valid corresponding lock.

**Permanently stuck funds**: The canonical transaction (H2, same `requestNonce`, different `txHash`) is included in the new canonical chain. The user's assets are locked in the source bridge. Because the vote for that nonce is already closed (or `lowerHandleNonce` has advanced past it), neither the normal event handler nor the VTR recovery path can process H2. There is no emergency withdrawal function in the bridge contracts. The assets are permanently irrecoverable.

---

### Likelihood Explanation

The Kaia main chain uses Istanbul BFT and has finality, making re-orgs negligible there. However, the service chain (child chain) does not guarantee the same finality properties and can experience re-orgs. The bridge operator subscribes to events on the service chain. A re-org of even one block on the service chain is sufficient to trigger this condition. The likelihood is low-to-medium for active service chains, but the impact when triggered is permanent loss of bridged assets.

---

### Recommendation

1. **Check `log.Removed` before processing**: In `ProcessRequestEvent` and `AddRequestValueTransferEvents`, skip any event where `ev.GetRaw().Removed == true`.

2. **Add confirmation depth**: Do not process a `RequestValueTransfer` event until it has been confirmed by a configurable number of blocks (e.g., `confirmations` parameter), reducing re-org exposure.

3. **Add an emergency recovery function** to the bridge contract (owner-only) that can re-open a closed nonce vote or directly refund locked assets when a canonical event cannot be processed.

---

### Proof of Concept

```
Source chain (service chain):
  Block N  : tx H1 emits RequestValueTransfer(nonce=5, value=100 KLAY)
             → KLAY locked in source bridge

  [Re-org occurs: block N replaced by block N']

  Block N' : tx H2 emits RequestValueTransfer(nonce=5, value=100 KLAY)
             → KLAY locked in source bridge (canonical)

Bridge operator subscription delivers:
  1. H1 log with Removed=true  → ProcessRequestEvent(H1) → AddRequestValueTransferEvents(H1)
  2. H2 log with Removed=false → ProcessRequestEvent(H2) → AddRequestValueTransferEvents(H2)

Destination bridge:
  Operator calls handleKLAYTransfer(H1, ..., nonce=5, ...)
    → _voteValueTransfer(5) returns true (first vote)
    → handledRequestTx[H1] = true
    → handleNoncesToBlockNums[5] = blockNum
    → lowerHandleNonce advances past 5 (deletes closedValueTransferVotes[5])
    → 100 KLAY sent to recipient  ← unauthorized transfer based on removed event

  Operator calls handleKLAYTransfer(H2, ..., nonce=5, ...)
    → _lowerHandleNonceCheck(5): lowerHandleNonce > 5 → REVERT "removed vote"
    OR (if lowerHandleNonce not yet advanced):
    → _voteValueTransfer(5) returns false (vote closed) → silent return

Result:
  - Recipient received 100 KLAY on destination (based on invalid H1)
  - User's 100 KLAY from canonical H2 is permanently locked in source bridge
  - No recovery path exists in the bridge contracts
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** node/sc/sub_event_handler.go (L71-86)
```go
func (cce *ChildChainEventHandler) ProcessRequestEvent(ev IRequestValueTransferEvent) error {
	addr := ev.GetRaw().Address

	handleBridgeAddr := cce.subbridge.bridgeManager.GetCounterPartBridgeAddr(addr)
	if handleBridgeAddr == (common.Address{}) {
		return fmt.Errorf("there is no counter part bridge of the bridge(%v)", addr.String())
	}

	handleBridgeInfo, ok := cce.subbridge.bridgeManager.GetBridgeInfo(handleBridgeAddr)
	if !ok {
		return fmt.Errorf("there is no counter part bridge info(%v) of the bridge(%v)", handleBridgeAddr.String(), addr.String())
	}

	// TODO-Kaia need to manage the size limitation of pending event list.
	handleBridgeInfo.AddRequestValueTransferEvents([]IRequestValueTransferEvent{ev})
	return nil
```

**File:** node/sc/bridge_manager.go (L401-425)
```go
// AddRequestValueTransferEvents adds events into the pendingRequestEvent.
func (bi *BridgeInfo) AddRequestValueTransferEvents(evs []IRequestValueTransferEvent) {
	for _, ev := range evs {
		if bi.pendingRequestEvent.Len() > maxPendingNonceDiff {
			flatten := bi.pendingRequestEvent.Flatten()
			maxNonce := flatten[len(flatten)-1].Nonce()
			if ev.Nonce() >= maxNonce || bi.pendingRequestEvent.Exist(ev.Nonce()) {
				continue
			}
			bi.pendingRequestEvent.Remove(maxNonce)
			vtPendingRequestEventCounter.Dec(1)
			logger.Trace("List is full but add requestValueTransfer ", "newNonce", ev.Nonce(), "removedNonce", maxNonce)
		}

		bi.SetRequestNonceFromCounterpart(ev.GetRequestNonce() + 1)
		bi.pendingRequestEvent.Put(ev)
		vtPendingRequestEventCounter.Inc(1)
	}
	logger.Trace("added pending request events to the bridge info:", "bi.pendingRequestEvent", bi.pendingRequestEvent.Len())

	select {
	case bi.newEvent <- struct{}{}:
	default:
	}
}
```

**File:** node/sc/bridge_manager.go (L1084-1124)
```go
// Loop handles subscribed event messages.
func (bm *BridgeManager) loop(
	addr common.Address,
	chanReqVT <-chan *bridgecontract.BridgeRequestValueTransfer,
	chanReqVTencoded <-chan *bridgecontract.BridgeRequestValueTransferEncoded,
	chanHandleVT <-chan *bridgecontract.BridgeHandleValueTransfer,
	reqVTevSub, reqVTencodedEvSub event.Subscription,
	handleEventSub event.Subscription,
) {
	defer reqVTevSub.Unsubscribe()
	defer reqVTencodedEvSub.Unsubscribe()
	defer handleEventSub.Unsubscribe()

	bi, ok := bm.GetBridgeInfo(addr)
	if !ok {
		logger.Error("bridge information is missing")
		return
	}

	// TODO-Kaia change goroutine logic for performance
	for {
		select {
		case <-bi.closed:
			return
		case ev := <-chanReqVT:
			bm.reqVTevFeeder.Send(RequestValueTransferEvent{ev})
		case ev := <-chanReqVTencoded:
			bm.reqVTevEncodedFeeder.Send(RequestValueTransferEncodedEvent{ev})
		case ev := <-chanHandleVT:
			bm.handleEventFeeder.Send(&HandleValueTransferEvent{ev})
		case err := <-reqVTevSub.Err():
			logger.Info("Contract Event Loop Running Stop by receivedSub.Err()", "err", err)
			return
		case err := <-reqVTencodedEvSub.Err():
			logger.Info("Contract Event Loop Running Stop by receivedSub.Err()", "err", err)
			return
		case err := <-handleEventSub.Err():
			logger.Info("Contract Event Loop Running Stop by withdrawSub.Err()", "err", err)
			return
		}
	}
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L74-99)
```text
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

**File:** contracts/service_chain/bridge/BridgeHandledRequests.sol (L19-25)
```text
contract BridgeHandledRequests {
    // TODO-Klaytn-Servicechain handleTxHash can be saved after Klaytn supports it.
    mapping(bytes32 => bool) public handledRequestTx;

    function _setHandledRequestTxHash(bytes32 _requestTxHash) internal {
        handledRequestTx[_requestTxHash] = true;
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
