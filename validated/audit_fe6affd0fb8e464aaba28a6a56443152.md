### Title
Missing Pending-Transfer Guard in `doDeregisterBridge` Silently Abandons In-Flight Bridged-Asset Transfers — (File: node/sc/api_bridge.go)

---

### Summary

`doDeregisterBridge` removes a bridge pair from the service-chain bridge system without verifying that all value-transfer requests have been handled. When the function is called while unprocessed KAIA/ERC20/ERC721 transfers exist, the processing loop is terminated and the recovery mechanism is deleted, leaving the locked assets permanently stranded in the source bridge contract.

---

### Finding Description

`doDeregisterBridge` in `node/sc/api_bridge.go` (lines 347–378) performs the following steps:

1. Validates the bridge pair.
2. If subscribed, calls `UnsubscribeEvent` on both child and parent bridges and calls `DeleteRecovery`.
3. Deletes the journal entry.
4. Calls `DeleteBridgeInfo` for both child and parent addresses. [1](#0-0) 

`DeleteBridgeInfo` closes the `bi.closed` channel, which terminates the `bi.loop()` goroutine that drives `processingPendingRequestEvents`: [2](#0-1) [3](#0-2) 

`BridgeInfo` tracks the gap between received and handled transfers via `requestNonceFromCounterPart` and `lowerHandleNonce`: [4](#0-3) 

The `GetBridgeInformation` API already exposes `pendingEventSize` and the nonce gap, confirming the system is aware of in-flight state: [5](#0-4) 

**No check is performed** in `doDeregisterBridge` to verify that `requestNonceFromCounterPart == lowerHandleNonce` (all requests handled) or that `pendingRequestEvent.Len() == 0` before proceeding with removal. The `DeleteRecovery` call also removes the `valueTransferRecovery` mechanism, which is the only automated path to replay missed transfers: [6](#0-5) 

The source bridge contract (`BridgeTransferKLAY`, `BridgeTransferERC20`) holds the locked assets on-chain. Without the operator submitting `handleKLAYTransfer` / `handleERC20Transfer` on the destination bridge, those assets are never released: [7](#0-6) 

---

### Impact Explanation

When `subbridge_deregisterBridge` is called while `requestNonceFromCounterPart > lowerHandleNonce`:

- The in-memory `pendingRequestEvent` queue is discarded (loop goroutine exits on `bi.closed`).
- The `valueTransferRecovery` for this bridge pair is deleted, removing the automated replay path.
- KAIA or ERC20/ERC721 tokens locked in the source bridge contract are never unlocked on the destination chain.
- The affected users' assets are permanently stranded unless the operator manually re-registers the bridge and re-triggers recovery — an undocumented and error-prone remediation path.

This directly matches the allowed impact: **unauthorized loss of bridged assets** due to a missing invariant check in a bridge-path function.

---

### Likelihood Explanation

The `subbridge_deregisterBridge` RPC is a normal operator maintenance action. An operator may call it:

- During a bridge migration or upgrade.
- After stopping the bridge (`setRunningStatus(false)`) without waiting for all in-flight transfers to settle.
- Believing the bridge is idle based on the source chain's `requestNonce` without cross-checking the destination chain's `lowerHandleNonce`.

The nonce gap is not surfaced as a warning or error during deregistration, making accidental invocation with pending transfers plausible.

---

### Recommendation

Add a pre-condition check in `doDeregisterBridge` before removing bridge state:

```go
func (sb *SubBridgeAPI) doDeregisterBridge(cBridgeAddr common.Address, pBridgeAddr common.Address) error {
    if !sb.subBridge.bridgeManager.IsValidBridgePair(cBridgeAddr, pBridgeAddr) {
        return ErrInvalidBridgePair
    }

    cBi, _ := sb.subBridge.bridgeManager.GetBridgeInfo(cBridgeAddr)
    pBi, _ := sb.subBridge.bridgeManager.GetBridgeInfo(pBridgeAddr)

    // Reject deregistration if either direction has unhandled transfers.
    if cBi != nil && cBi.requestNonceFromCounterPart > cBi.lowerHandleNonce {
        return errors.New("child bridge has pending value transfers; handle all transfers before deregistering")
    }
    if pBi != nil && pBi.requestNonceFromCounterPart > pBi.lowerHandleNonce {
        return errors.New("parent bridge has pending value transfers; handle all transfers before deregistering")
    }
    // ... rest of removal logic
```

This mirrors the recommendation in the external report: verify zero pending state before removing from the queue.

---

### Proof of Concept

1. Deploy a child/parent bridge pair and register it via `subbridge_registerBridge`.
2. Subscribe via `subbridge_subscribeBridge`.
3. Send a KAIA transfer via `requestKLAYTransfer` on the child bridge — this increments `requestNonce` on the child and queues a pending event in the parent `BridgeInfo`.
4. Before the operator's loop submits `handleKLAYTransfer` on the parent bridge, call `subbridge_deregisterBridge`.
5. Observe: `doDeregisterBridge` succeeds with no error. The `bi.closed` channel is closed, the loop exits, the recovery is deleted.
6. The KAIA is locked in the child bridge contract. The parent bridge's `lowerHandleNonce` remains at 0. The user's funds are stranded.

The `GetBridgeInformation` call before step 4 would show `pendingEventSize > 0` and `requestNonce > lowerHandleNonce`, confirming the unhandled state that the deregistration path ignores. [8](#0-7) [9](#0-8)

### Citations

**File:** node/sc/api_bridge.go (L272-293)
```go
func (sb *SubBridgeAPI) GetBridgeInformation(bridgeAddr common.Address) (map[string]interface{}, error) {
	if ctBridge := sb.subBridge.bridgeManager.GetCounterPartBridgeAddr(bridgeAddr); ctBridge == (common.Address{}) {
		return nil, ErrInvalidBridgePair
	}

	bi, ok := sb.subBridge.bridgeManager.GetBridgeInfo(bridgeAddr)
	if !ok {
		return nil, ErrNoBridgeInfo
	}

	bi.UpdateInfo()

	return map[string]interface{}{
		"isRunning":        bi.isRunning,
		"requestNonce":     bi.requestNonceFromCounterPart,
		"handleNonce":      bi.handleNonce,
		"lowerHandleNonce": bi.lowerHandleNonce,
		"counterPart":      bi.counterpartAddress,
		"onServiceChain":   bi.onChildChain,
		"isSubscribed":     bi.subscribed,
		"pendingEventSize": bi.pendingRequestEvent.Len(),
	}, nil
```

**File:** node/sc/api_bridge.go (L347-378)
```go
func (sb *SubBridgeAPI) doDeregisterBridge(cBridgeAddr common.Address, pBridgeAddr common.Address) error {
	if !sb.subBridge.bridgeManager.IsValidBridgePair(cBridgeAddr, pBridgeAddr) {
		return ErrInvalidBridgePair
	}

	bm := sb.subBridge.bridgeManager
	bm.journal.cacheMu.Lock()
	journal := bm.journal.cache[cBridgeAddr]

	if journal.Subscribed {
		bm.UnsubscribeEvent(journal.ChildAddress)
		bm.UnsubscribeEvent(journal.ParentAddress)

		bm.DeleteRecovery(cBridgeAddr, pBridgeAddr)
	}

	delete(bm.journal.cache, cBridgeAddr)
	bm.journal.cacheMu.Unlock()

	if err := bm.journal.rotate(bm.GetAllBridge()); err != nil {
		logger.Warn("failed to rotate bridge journal", "err", err, "cBridge", cBridgeAddr.String(), "pBridge", pBridgeAddr.String())
	}

	if err := bm.DeleteBridgeInfo(cBridgeAddr); err != nil {
		logger.Warn("failed to Delete child chain bridge info", "err", err, "bridge", cBridgeAddr.String())
	}

	if err := bm.DeleteBridgeInfo(pBridgeAddr); err != nil {
		logger.Warn("failed to Delete parent chain bridge info", "err", err, "bridge", pBridgeAddr.String())
	}
	return nil
}
```

**File:** node/sc/bridge_manager.go (L105-116)
```go
	pendingRequestEvent *bridgepool.ItemSortedMap

	isRunning                   bool
	handleNonce                 uint64 // the nonce from the handle value transfer event from the bridge.
	lowerHandleNonce            uint64 // the lower handle nonce from the bridge.
	requestNonceFromCounterPart uint64 // the nonce from the request value transfer event from the counter part bridge.
	requestNonce                uint64 // the nonce from the request value transfer event from the counter part bridge.

	newEvent chan struct{}
	closed   chan struct{}

	handledEvent *bridgepool.ItemSortedMap
```

**File:** node/sc/bridge_manager.go (L173-191)
```go
func (bi *BridgeInfo) loop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	logger.Info("start bridge loop", "addr", bi.address.String(), "onChildChain", bi.onChildChain)

	for {
		select {
		case <-bi.newEvent:
			bi.processingPendingRequestEvents()

		case <-ticker.C:
			bi.processingPendingRequestEvents()

		case <-bi.closed:
			logger.Info("stop bridge loop", "addr", bi.address.String(), "onChildChain", bi.onChildChain)
			return
		}
	}
```

**File:** node/sc/bridge_manager.go (L239-260)
```go
// processingPendingRequestEvents handles pending request value transfer events of the bridge.
func (bi *BridgeInfo) processingPendingRequestEvents() {
	ReadyEvent := bi.GetReadyRequestValueTransferEvents()
	if ReadyEvent == nil {
		return
	}

	logger.Trace("Get ready request value transfer event", "len(readyEvent)", len(ReadyEvent), "len(pendingEvent)", bi.pendingRequestEvent.Len())

	for idx, ev := range ReadyEvent {
		if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
			logger.Trace("handled requests can be ignored", "RequestNonce", ev.GetRequestNonce(), "lowerHandleNonce", bi.lowerHandleNonce)
			continue
		}

		if err := bi.handleRequestValueTransferEvent(ev); err != nil {
			bi.AddRequestValueTransferEvents(ReadyEvent[idx:])
			logger.Error("Failed handle request value transfer event", "err", err, "len(RePutEvent)", len(ReadyEvent[idx:]))
			return
		}
	}
}
```

**File:** node/sc/bridge_manager.go (L666-679)
```go
// DeleteBridgeInfo deletes the bridge info of the specified address.
func (bm *BridgeManager) DeleteBridgeInfo(addr common.Address) error {
	bm.bridgesMu.Lock()
	defer bm.bridgesMu.Unlock()

	bi := bm.bridges[addr]
	if bi == nil {
		return ErrNoBridgeInfo
	}

	close(bi.closed)

	delete(bm.bridges, addr)
	return nil
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-99)
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
```
