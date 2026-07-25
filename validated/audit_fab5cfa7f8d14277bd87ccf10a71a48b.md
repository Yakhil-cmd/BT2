### Title
`handleKLAYTransfer()` Permanent Delivery Failure Causes KAIA Permanently Stuck in Source Bridge — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer()` delivers KAIA to `_to` via a low-level `.call.value()`. If `_to` is a contract that permanently rejects KAIA (no payable fallback), every operator attempt reverts, the request nonce is never marked handled, the Value Transfer Recovery (VTR) loop retries forever, and the user's KAIA locked in the source bridge is permanently irrecoverable. No rescue or cancel path exists anywhere in the `Bridge` contract hierarchy.

---

### Finding Description

When a user calls `requestKLAYTransfer` on the child-chain bridge, their KAIA is locked in that contract and a `RequestValueTransfer` event is emitted. Operators observe the event and call `handleKLAYTransfer` on the counterpart bridge to release KAIA to `_to`.

The delivery sequence in `handleKLAYTransfer` is:

```solidity
// BridgeTransferKLAY.sol lines 75-99
_lowerHandleNonceCheck(_requestedNonce);
if (!_voteValueTransfer(_requestedNonce)) { return; }

_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);
emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");   // ← reverts entire tx
``` [1](#0-0) 

Because `require(ok, ...)` is the last statement, a failed delivery reverts the **entire transaction**, including all nonce-accounting state changes. The nonce is never recorded in `handleNoncesToBlockNums`, `_updateHandleNonce` is never committed, and `lowerHandleNonce` never advances.

The VTR loop in `vt_recovery.go` detects the gap between `requestNonce` and `lowerHandleNonce` and re-queues the event indefinitely:

```go
// vt_recovery.go – recoverPendingEvents
vtr.pBridgeInfo.AddRequestValueTransferEvents(events)
``` [2](#0-1) 

The recovery hint comparison that drives this loop:

```go
hint.requestNonce = requestNonce   // from source bridge
hint.handleNonce  = handleNonce    // from dest bridge (never advances)
``` [3](#0-2) 

The `Bridge` contract (the complete contract hierarchy) contains **no** `withdraw`, `rescue`, or cancel function. The only KAIA-related owner functions are `lockKLAY`/`unlockKLAY` (which only gate new requests) and `chargeWithoutEvent` (which only adds KAIA). There is no path for the owner or the original sender to reclaim the locked KAIA. [4](#0-3) 

---

### Impact Explanation

The KAIA deposited by the user into the source bridge is permanently locked. The destination bridge's KAIA pool is unaffected (the delivery tx always reverts before consuming it), but the source bridge's balance grows monotonically with each stuck request and can never be drained. This constitutes an **unauthorized permanent lock of KAIA in a system-managed bridge contract** — a direct match to the allowed-impact gate ("unauthorized … affecting KAIA, bridged assets, or system-managed funds").

---

### Likelihood Explanation

`_to` is a free parameter supplied by the user at `requestKLAYTransfer` time. Any of the following triggers the permanent failure:

- `_to` is a contract with no `payable` fallback/receive function (extremely common — e.g., multisigs, DAOs, token contracts).
- `_to` is a contract whose receive function reverts unconditionally.
- `_to` self-destructed between the request and the handle.

The user may not know at request time that the destination contract rejects KAIA. The likelihood is **Medium**, matching the external report's classification.

---

### Recommendation

1. **Fallback-to-sender on delivery failure**: if `_to.call.value(_value)("")` returns `ok == false`, transfer the KAIA to `_from` (the original requester) instead of reverting, and still mark the nonce as handled.
2. **Alternatively, add a rescue function**: allow the bridge owner to withdraw KAIA for a specific stuck nonce and redirect it to `_from`, after the nonce has been confirmed permanently undeliverable.
3. **Validate `_to` at request time**: reject requests where `_to` is a known non-payable contract, though this is difficult to enforce on-chain.

---

### Proof of Concept

1. Deploy `Bridge` (non-mintBurn) on both child and parent chains; fund the parent bridge with KAIA.
2. Deploy a contract `Rejector` with no payable fallback on the parent chain.
3. Call `requestKLAYTransfer(Rejector, value, "")` on the child bridge — KAIA is locked in child bridge.
4. Operators call `handleKLAYTransfer(..., Rejector, value, nonce, ...)` on the parent bridge.
5. `Rejector.receive()` reverts → `ok == false` → `require` reverts the entire tx.
6. Observe: `lowerHandleNonce` on parent bridge is unchanged; `handleNoncesToBlockNums[nonce] == 0`.
7. VTR re-queues the event; step 4–6 repeat indefinitely.
8. Confirm: child bridge KAIA balance is permanently non-zero; no owner function can drain it. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** node/sc/vt_recovery.go (L166-198)
```go
}

// updateRecoveryHint updates hints for value transfers on the both side.
// One is from child chain to parent chain, the other is from parent chain to child chain value transfers.
// The hint includes a block number to begin search, request nonce and handle nonce.
func (vtr *valueTransferRecovery) updateRecoveryHint() error {
	if vtr.cBridgeInfo == nil {
		return errors.New("child chain bridge is nil")
	}
	if vtr.pBridgeInfo == nil {
		return errors.New("parent chain bridge is nil")
	}

	var err error
	vtr.child2parentHint, err = updateRecoveryHintFromTo(vtr.child2parentHint, vtr.cBridgeInfo, vtr.pBridgeInfo)
	if err != nil {
		return err
	}

	vtr.parent2childHint, err = updateRecoveryHintFromTo(vtr.parent2childHint, vtr.pBridgeInfo, vtr.cBridgeInfo)
	if err != nil {
		return err
	}

	// Update the hint for the initial status.
	if !vtr.isRunning {
		vtr.child2parentHint.prevHandleNonce = vtr.child2parentHint.handleNonce
		vtr.parent2childHint.prevHandleNonce = vtr.parent2childHint.handleNonce
		vtr.child2parentHint.candidate = true
		vtr.parent2childHint.candidate = true
	}

	return nil
```

**File:** node/sc/vt_recovery.go (L216-234)
```go
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

	if prevHint != nil {
		hint.prevHandleNonce = prevHint.handleNonce
		hint.candidate = prevHint.candidate
	}
	hint.handleNonce = handleNonce
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

**File:** contracts/service_chain/bridge/Bridge.sol (L25-30)
```text
contract Bridge is BridgeCounterPart, BridgeTransferKLAY, BridgeTransferERC20, BridgeTransferERC721 {
    uint64 public constant VERSION = 1;

    constructor(bool _modeMintBurn) BridgeTransfer(_modeMintBurn) public payable {
    }
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
