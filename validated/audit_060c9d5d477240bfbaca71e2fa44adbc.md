### Title
Service-Chain Bridge KLAY Transfer Permanently Stuck When Recipient Contract Rejects KLAY, Freezing `lowerHandleNonce` and VT Recovery — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` performs all nonce-accounting state updates — including `_updateHandleNonce` which advances `lowerHandleNonce` and `recoveryBlockNumber` — **before** the actual KLAY transfer. If the transfer to `_to` fails (e.g., `_to` is a contract whose `fallback()` reverts or consumes all gas), the `require(ok, ...)` causes the entire transaction to revert, rolling back every state change. Because `handleNoncesToBlockNums[_requestedNonce]` is never durably set, `lowerHandleNonce` can never advance past that nonce. The VT recovery system then permanently retries the stuck nonce, `recoveryBlockNumber` is frozen, and `handleNoncesToBlockNums` / `closedValueTransferVotes` storage accumulates without bound for all subsequent nonces.

---

### Finding Description

In `BridgeTransferKLAY.sol`, `handleKLAYTransfer` executes in this order:

```
1. _lowerHandleNonceCheck(_requestedNonce)
2. _voteValueTransfer(_requestedNonce)          ← vote state committed only if threshold not met
3. _setHandledRequestTxHash(_requestTxHash)     ┐
4. handleNoncesToBlockNums[N] = _requestedBlockNumber  │ all rolled back
5. _updateHandleNonce(N)                        │ if step 7 reverts
6. emit HandleValueTransfer(...)                ┘
7. (bool ok,) = _to.call.value(_value)("")
8. require(ok, "handleKLAYTransfer: transfer failed")
``` [1](#0-0) 

When the threshold is reached and `_voteValueTransfer` returns `true`, execution reaches step 7. If `_to` is a contract whose `fallback()` reverts, `ok == false` and `require` at step 8 reverts the entire transaction. All state changes from steps 3–6 are rolled back:

- `handleNoncesToBlockNums[N]` stays `0`
- `_updateHandleNonce` is undone, so `lowerHandleNonce` stays at `N`
- `recoveryBlockNumber` is not updated

`_updateHandleNonce` advances `lowerHandleNonce` by scanning the consecutive sequence starting at `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
``` [2](#0-1) 

Since `handleNoncesToBlockNums[N]` is always `0` (rolled back every time), the loop terminates immediately and `lowerHandleNonce` is permanently stuck at `N`. Even when nonces `N+1`, `N+2`, … are successfully handled, their `handleNoncesToBlockNums` entries are set but the loop never reaches them because it stops at `N`. Consequently:

1. `recoveryBlockNumber` is frozen at the block before nonce `N`.
2. `handleNoncesToBlockNums[N+1]`, `handleNoncesToBlockNums[N+2]`, … accumulate and are never deleted.
3. `closedValueTransferVotes[N+1]`, `closedValueTransferVotes[N+2]`, … accumulate and are never deleted.

The Go-level VT recovery system reads `recoveryBlockNumber` to determine where to start scanning for pending events: [3](#0-2) 

Because `recoveryBlockNumber` is frozen, the recovery system perpetually re-discovers nonce `N` as pending and re-submits it via `AddRequestValueTransferEvents` → `processingPendingRequestEvents` → `handleRequestValueTransferEvent`: [4](#0-3) 

Each retry submits a transaction that reverts on-chain, wasting gas indefinitely. There is no owner-callable function to manually advance `lowerHandleNonce` or skip a stuck nonce.

---

### Impact Explanation

- **`lowerHandleNonce` permanently frozen** at the attacker's nonce `N`; `recoveryBlockNumber` frozen at the block preceding `N`.
- **Unbounded storage growth**: `handleNoncesToBlockNums` and `closedValueTransferVotes` entries for all nonces `> N` are never deleted, increasing gas cost for every future `handleKLAYTransfer` call.
- **Infinite gas drain** on the bridge operator account: the VT recovery loop keeps re-submitting the failing transaction.
- **No admin escape hatch**: the contract has no function to skip or override a stuck nonce; remediation requires a contract upgrade.

The corrupted state values are concrete: `lowerHandleNonce` (should equal `N+1` after `N` is processed, stays at `N`), `recoveryBlockNumber` (should advance with each handled nonce, stays at block `B_N - 1`).

---

### Likelihood Explanation

Any unprivileged user can trigger this by calling `requestKLAYTransfer` with `_to` set to a contract whose `fallback()` reverts or consumes all gas. The attacker controls the timing (choosing a moment when the bridge has high pending volume to maximise disruption). No operator or validator collusion is required. [5](#0-4) 

---

### Recommendation

Move the KLAY transfer **before** the nonce-accounting state updates, or wrap the transfer in a `try`/`catch`-equivalent pattern (low-level call with a checked result that does not revert the whole transaction). If the transfer fails, either:

1. Emit a failure event and advance the nonce anyway (crediting the KLAY back to the bridge balance), or
2. Add an owner-callable `skipHandleNonce(uint64 nonce)` that manually sets `handleNoncesToBlockNums[nonce]` to a sentinel value so `_updateHandleNonce` can advance past it.

---

### Proof of Concept

```solidity
// Attacker deploys this on the destination chain
contract KLAYRejecter {
    fallback() external payable { revert("no KLAY"); }
}
```

1. Attacker calls `requestKLAYTransfer(address(KLAYRejecter), value, "")` on the source bridge — emits `RequestValueTransfer` with nonce `N`.
2. Operators observe the event and call `handleKLAYTransfer(..., address(KLAYRejecter), value, N, ...)` on the destination bridge.
3. Threshold is met; execution reaches `_to.call.value(value)("")` → `KLAYRejecter.fallback()` reverts → `require(ok)` reverts the whole tx.
4. `handleNoncesToBlockNums[N]` stays `0`; `lowerHandleNonce` stays at `N`.
5. VT recovery reads `recoveryBlockNumber` (frozen), finds nonce `N` pending, re-adds it to the queue.
6. Steps 2–5 repeat indefinitely; `lowerHandleNonce` and `recoveryBlockNumber` never advance; storage for all subsequent nonces accumulates without bound. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L75-100)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
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

**File:** node/sc/vt_recovery.go (L211-228)
```go
	hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
	if err != nil {
		return nil, err
	}

	requestNonce, err := from.bridge.RequestNonce(nil)
	if err != nil {
		return nil, err
	}
	from.SetRequestNonce(requestNonce)
	to.SetRequestNonceFromCounterpart(requestNonce)
	hint.requestNonce = requestNonce

	handleNonce, err := to.bridge.LowerHandleNonce(nil)
	if err != nil {
		return nil, err
	}
	to.UpdateLowerHandleNonce(handleNonce)
```

**File:** node/sc/vt_recovery.go (L382-412)
```go
func (vtr *valueTransferRecovery) recoverPendingEvents() error {
	defer func() {
		vtr.childEvents = []IRequestValueTransferEvent{}
		vtr.parentEvents = []IRequestValueTransferEvent{}
	}()

	if len(vtr.childEvents) > 0 {
		logger.Warn("VT Recovery : Child -> Parent Chain", "cBridge", vtr.cBridgeInfo.address.String(), "events", len(vtr.childEvents))
	}

	vtRequestEventMeter.Mark(int64(len(vtr.childEvents)))
	vtRecoveredRequestEventMeter.Mark(int64(len(vtr.childEvents)))

	events := make([]IRequestValueTransferEvent, len(vtr.childEvents))
	for i, event := range vtr.childEvents {
		events[i] = event
	}
	vtr.pBridgeInfo.AddRequestValueTransferEvents(events)

	if len(vtr.parentEvents) > 0 {
		logger.Warn("VT Recovery : Parent -> Child Chain", "pBridge", vtr.pBridgeInfo.address.String(), "events", len(vtr.parentEvents))
	}

	vtHandleEventMeter.Mark(int64(len(vtr.parentEvents)))
	events = make([]IRequestValueTransferEvent, len(vtr.parentEvents))
	for i, event := range vtr.parentEvents {
		events[i] = event
	}
	vtr.cBridgeInfo.AddRequestValueTransferEvents(events)

	return nil
```

**File:** node/sc/bridge_manager.go (L239-259)
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
```
