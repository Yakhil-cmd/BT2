### Title
Sequential Bridge Request Nonce Queue Allows Griefing to Delay Legitimate Value-Transfer Settlement — (`contracts/service_chain/bridge/BridgeTransfer.sol`, `node/sc/bridge_manager.go`)

---

### Summary

Any user can call `requestKLAYTransfer` (or the ERC-20/ERC-721 equivalents) on the source-chain bridge contract with a minimal value (as low as 1 wei when `feeOfKLAY = 0`). Each call consumes one monotonically-increasing `requestNonce`. The bridge operator's Go-side event loop (`processingPendingRequestEvents`) pops and handles these events in strict nonce order. A malicious user who front-fills the nonce space with thousands of dust requests forces the operator to submit a `handleKLAYTransfer` on-chain transaction for every one of those dust requests before a legitimate user's transfer can be settled on the destination chain. The legitimate user's KAIA is locked inside the bridge contract for the entire duration.

---

### Finding Description

**Source-chain side — nonce assignment (no minimum value guard)**

Every call to `_requestKLAYTransfer` emits a `RequestValueTransfer` event and increments `requestNonce`:

```solidity
// BridgeTransferKLAY.sol
require(isRunning, "stopped bridge");
require(msg.value > _feeLimit, "insufficient amount");   // only guard: value > feeLimit
...
requestNonce++;
```

When `feeOfKLAY == 0` (the contract default), `_feeLimit == 0`, so the only requirement is `msg.value > 0`. An attacker can submit N requests each carrying 1 wei. [1](#0-0) [2](#0-1) 

**Destination-chain side — sequential nonce processing in the Go bridge manager**

`processingPendingRequestEvents` calls `GetReadyRequestValueTransferEvents` → `GetPendingRequestEvents` → `Pop(maxPendingNonceDiff / 2)`. `Pop` always removes the *minimum-nonce* items first:

```go
// bridge_manager.go
func (bi *BridgeInfo) GetPendingRequestEvents() []IRequestValueTransferEvent {
    ready := bi.pendingRequestEvent.Pop(maxPendingNonceDiff / 2)   // pops lowest nonces first
    ...
}
```

The loop then calls `handleRequestValueTransferEvent` for each event in nonce order, submitting one on-chain `handleKLAYTransfer` transaction per event:

```go
for idx, ev := range ReadyEvent {
    if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
        continue
    }
    if err := bi.handleRequestValueTransferEvent(ev); err != nil {
        bi.AddRequestValueTransferEvents(ReadyEvent[idx:])
        return
    }
}
``` [3](#0-2) [4](#0-3) 

**`lowerHandleNonce` stalls until the gap is filled**

`_updateHandleNonce` advances `lowerHandleNonce` only through a contiguous run of already-handled nonces (capped at 200 per call). If nonces 0–N-1 are unhandled, `lowerHandleNonce` stays at 0, and `recoveryBlockNumber` is not updated:

```solidity
uint64 limit = lowerHandleNonce + 200;
if (limit > upperHandleNonce) { limit = upperHandleNonce; }
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
``` [5](#0-4) 

The existing test `TestBridgeRequestHandleGasUsed` explicitly documents this behaviour: handling nonces 501–999 before 500 leaves `lowerHandleNonce` stuck at 500 until nonce 500 is finally processed. [6](#0-5) 

**`maxPendingNonceDiff` cap does not prevent the attack**

The in-memory cap (`maxPendingNonceDiff = 1000`) limits the Go-side pending queue, but the attacker's events are already committed on-chain. The value-transfer recovery path (`retrievePendingEventsFrom`) re-reads them from chain logs and re-injects them, so the operator cannot simply discard them.
<cite repo="hirayap/kaia--

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-124)
```text
    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");

        uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);

        emit RequestValueTransfer(
            TokenType.KLAY,
            msg.sender,
            _to,
            address(0),
            msg.value.sub(_feeLimit),
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L30-30)
```text
    uint256 public feeOfKLAY = 0;
```

**File:** node/sc/bridge_manager.go (L229-260)
```go
func (bi *BridgeInfo) GetPendingRequestEvents() []IRequestValueTransferEvent {
	ready := bi.pendingRequestEvent.Pop(maxPendingNonceDiff / 2)
	readyEvent := make([]IRequestValueTransferEvent, len(ready))
	for i, item := range ready {
		readyEvent[i] = item.(IRequestValueTransferEvent)
	}
	vtPendingRequestEventCounter.Dec((int64)(len(ready)))
	return readyEvent
}

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

**File:** node/sc/bridgepool/sorted_map_list.go (L130-144)
```go
func (m *ItemSortedMap) Pop(count int) items {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Otherwise start accumulating incremental events
	var ready items
	for m.index.Len() > 0 && len(ready) < count {
		nonce := (*m.index)[0]
		ready = append(ready, m.items[nonce])
		delete(m.items, nonce)
		heap.Pop(m.index)
	}

	return ready
}
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-156)
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
```

**File:** node/sc/bridge_test.go (L1228-1244)
```go
	// handle 501 ~ 999 nonce
	for i := 501; i < 1000; i++ {
		handleFunc(i)
	}

	lowerHandleNonce, _ = b.LowerHandleNonce(nil)
	assert.Equal(t, uint64(500), lowerHandleNonce)
	upperHandleNonce, _ = b.UpperHandleNonce(nil)
	assert.Equal(t, uint64(999), upperHandleNonce)

	// This 500 nonce handle checks whether the handle transaction which has a loop failed.
	handleFunc(500)

	lowerHandleNonce, _ = b.LowerHandleNonce(nil)
	assert.Equal(t, uint64(701), lowerHandleNonce)
	upperHandleNonce, _ = b.UpperHandleNonce(nil)
	assert.Equal(t, uint64(999), upperHandleNonce)
```
