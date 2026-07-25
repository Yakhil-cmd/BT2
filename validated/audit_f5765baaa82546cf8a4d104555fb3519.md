### Title
Permanent Bridged-KLAY Loss via Reverting Recipient in `handleKLAYTransfer` — (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in the service-chain bridge pushes KLAY to `_to` via a low-level call **after** all nonce-state bookkeeping. If `_to` is a contract that consistently reverts on receiving KLAY, the transfer can never succeed. Because there is no operator-accessible skip or cancel path, the KLAY locked in the destination-chain bridge for that request nonce is permanently irrecoverable, while the corresponding source-chain KLAY remains locked in the source bridge.

---

### Finding Description

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` performs all nonce bookkeeping before making the external KLAY transfer:

```
_setHandledRequestTxHash(_requestTxHash);          // line 81
handleNoncesToBlockNums[_requestedNonce] = ...;    // line 83
_updateHandleNonce(_requestedNonce);               // line 84
emit HandleValueTransfer(...);                     // lines 86-96

(bool ok, ) = _to.call.value(_value)("");          // line 98
require(ok, "handleKLAYTransfer: transfer failed");// line 99
``` [1](#0-0) 

If `_to` is a contract that reverts on receiving KLAY (no payable fallback, or a deliberately reverting `receive`/fallback hook), the `require` on line 99 causes the entire transaction to revert. All state changes — including the nonce bookkeeping — are rolled back. The nonce is not consumed, so bridge operators can retry, but every retry fails identically.

There is no operator-accessible function to skip a stuck nonce, redirect KLAY to an alternative address, or cancel the pending transfer. The `_lowerHandleNonceCheck` guard only enforces `lowerHandleNonce <= _requestedNonce`: [2](#0-1) 

Because `handleNoncesToBlockNums[N]` is never written for the stuck nonce N, `_updateHandleNonce` for any later nonce scans from `lowerHandleNonce` and stops at N (where the mapping value is 0), leaving `lowerHandleNonce` permanently at N. Other nonces ≥ N can still be processed (they satisfy the check), so the DoS is scoped to the single stuck transfer — but that transfer's KLAY is permanently locked.

On the source chain, `_requestKLAYTransfer` accepts `msg.value` into the bridge contract and emits `RequestValueTransfer`: [3](#0-2) 

Once that event is emitted and the source-chain KLAY is held by the bridge, there is no cancel or refund path. The `processingPendingRequestEvents` loop in the Go relay layer re-queues failed events and retries: [4](#0-3) 

But if `_to` always reverts, every retry fails, and the KLAY is permanently stranded.

---

### Impact Explanation

The KLAY corresponding to the stuck request nonce is permanently locked in the destination-chain bridge contract. The user's source-chain KLAY (already held by the source bridge after `requestKLAYTransfer`) is irrecoverable. This is a permanent loss of bridged KLAY assets — an unauthorized effective burn of user funds held by the bridge system.

---

### Likelihood Explanation

Medium. The `_to` address is user-specified on the source chain. A contract recipient without a payable fallback, or one upgraded after the transfer was initiated to reject KLAY, triggers this condition. A malicious actor can also deliberately specify a reverting contract to permanently strand bridge liquidity for that nonce. The bridge relay has no detection or mitigation path.

---

### Recommendation

Adopt a **pull-over-push** pattern for KLAY delivery: instead of pushing KLAY to `_to` inside `handleKLAYTransfer`, record the pending withdrawal in a mapping (`pendingWithdrawals[_to] += _value`) and let `_to` (or an authorized party) pull the KLAY via a separate `withdraw()` call. Alternatively, add an operator-accessible function to redirect a stuck transfer to a fallback address after a configurable timeout, analogous to the recovery mechanism already present in the relay layer.

---

### Proof of Concept

1. Deploy a `Reverter` contract on the destination chain with no payable fallback (or one that explicitly calls `revert()`).
2. On the source chain, call `requestKLAYTransfer(reverterAddress, value, "")` — KLAY is locked in the source bridge.
3. Bridge operators observe the `RequestValueTransfer` event and call `handleKLAYTransfer(txHash, from, reverterAddress, value, nonce, blockNum, "")` on the destination chain.
4. `reverterAddress.call.value(value)("")` returns `ok = false`; `require` reverts the transaction.
5. All state changes roll back; the nonce is not consumed.
6. The relay re-queues and retries (`processingPendingRequestEvents`); every attempt fails identically.
7. The KLAY in the destination bridge is permanently locked. The user's source-chain KLAY is permanently lost with no recourse.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L81-99)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
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
