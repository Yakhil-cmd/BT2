### Title
Bridge Operator KAIA Drained via KLAY Transfer Request to Non-Payable Contract Address — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`_requestKLAYTransfer` (called by `requestKLAYTransfer` and the fallback) emits a `RequestValueTransfer` event with an arbitrary `_to` address and no validation that `_to` can receive KLAY. The bridge operator's Go-side handler unconditionally calls `handleKLAYTransfer` on the counterpart bridge, which performs a raw `.call.value(_value)("")` to `_to` and reverts if it fails. If `_to` is a contract that rejects KLAY, the handle transaction reverts, the nonce is not consumed, and the value-transfer recovery system re-queues the event indefinitely — draining the bridge operator's KAIA balance with no recourse.

---

### Finding Description

**Step 1 — No recipient validation at request time.**

`_requestKLAYTransfer` accepts any `_to` address:

```solidity
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal unlockedKLAY nonReentrant
{
    require(isRunning, "stopped bridge");
    require(msg.value > _feeLimit, "insufficient amount");
    uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);
    emit RequestValueTransfer(TokenType.KLAY, msg.sender, _to, address(0),
        msg.value.sub(_feeLimit), requestNonce, fee, _extraData);
    requestNonce++;
}
``` [1](#0-0) 

There is no check that `_to` is an EOA or a contract with a payable fallback. The event is emitted and the nonce is incremented regardless.

**Step 2 — Operator unconditionally calls `handleKLAYTransfer`.**

The Go bridge manager processes every `RequestValueTransfer` event and calls `HandleKLAYTransfer` on the counterpart bridge with the attacker-supplied `_to`:

```go
case KAIA:
    handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to,
        valueOrTokenId, requestNonce, blkNumber, extraData)
``` [2](#0-1) 

**Step 3 — `handleKLAYTransfer` reverts when `_to` rejects KLAY.**

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [3](#0-2) 

Because `require` is the last statement, the entire transaction reverts. All intermediate state changes — `_setHandledRequestTxHash`, `_updateHandleNonce`, `closedValueTransferVotes[nonce] = true` — are rolled back. The `lowerHandleNonce` does not advance.

**Step 4 — Recovery re-queues the event indefinitely.**

`valueTransferRecovery.Recover()` runs on a configurable ticker. It detects that `requestNonce != lowerHandleNonce` (the handle nonce is stuck) and re-queues the pending event:

```go
vtr.pBridgeInfo.AddRequestValueTransferEvents(events)
``` [4](#0-3) 

Because the vote is also reverted each time, `closedValueTransferVotes[nonce]` remains `false`, so operators can vote again. Each recovery cycle causes operators to submit a new `handleKLAYTransfer` transaction, pay gas, and revert — indefinitely.

---

### Impact Explanation

The bridge operator account is a system-managed fund whose KAIA balance pays for all `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` transactions. An attacker who drains this balance renders the bridge inoperable: the operator can no longer submit any handle transactions, permanently halting cross-chain value transfers. This constitutes an unauthorized, persistent fee charge against system-managed KAIA funds.

---

### Likelihood Explanation

`requestKLAYTransfer` is a public, permissionless function. Any account can call it with a non-payable contract address as `_to` while paying only the bridge fee (which can be zero if `feeOfKLAY == 0`) plus their own gas. The cost to the attacker is bounded and one-time; the cost to the bridge operator is unbounded and recurring. A single malicious request is sufficient to trigger the infinite retry loop.

---

### Recommendation

Add a recipient validation check inside `_requestKLAYTransfer` before emitting the event. The simplest approach is to reject contract addresses as `_to`:

```solidity
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal unlockedKLAY nonReentrant
{
    require(isRunning, "stopped bridge");
    require(msg.value > _feeLimit, "insufficient amount");
    // Reject contract recipients that cannot receive KLAY
    uint256 toCodeSize;
    assembly { toCodeSize := extcodesize(_to) }
    require(toCodeSize == 0, "recipient must be EOA");
    ...
}
```

Alternatively, mirror the pattern used in `TreasuryRebalance.sol`'s `isContractAddr` helper and reject non-payable contracts, or perform a dry-run check before emitting the event. [1](#0-0) 

---

### Proof of Concept

1. Deploy `RejectKLAY` on the counterpart chain:
   ```solidity
   contract RejectKLAY {
       // No payable fallback — any KLAY send reverts
   }
   ```

2. On the source chain, call:
   ```solidity
   bridge.requestKLAYTransfer{value: 1 ether}(
       address(rejectKLAY), // _to
       1 ether,             // _value (feeLimit = 0)
       ""
   );
   ```
   This emits `RequestValueTransfer` with `to = rejectKLAY` and increments `requestNonce`.

3. The bridge operator's Go daemon picks up the event and submits:
   ```go
   bridge.HandleKLAYTransfer(auth, txHash, from, rejectKLAY, 1e18, nonce, blockNum, nil)
   ```
   The transaction reverts at `require(ok, "handleKLAYTransfer: transfer failed")`. The operator pays gas and loses it. `lowerHandleNonce` remains unchanged.

4. `valueTransferRecovery.Recover()` fires on the next tick, detects the stuck nonce, and re-queues the event. The operator submits another failing transaction. This repeats every `VTRecoveryInterval` seconds until the operator's KAIA balance is exhausted. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
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

**File:** node/sc/bridge_manager.go (L332-337)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```

**File:** node/sc/vt_recovery.go (L102-128)
```go
	go func() {
		ticker := time.NewTicker(time.Duration(vtr.config.VTRecoveryInterval) * time.Second)
		defer func() {
			ticker.Stop()
			vtr.wg.Done()
		}()

		if err := vtr.Recover(); err != nil {
			logger.Warn("initial value transfer recovery is failed", "err", err)
		}

		vtr.isRunning = true

		for {
			select {
			case <-vtr.stopCh:
				logger.Info("value transfer recovery is stopped")
				return
			case <-ticker.C:
				if vtr.isRunning {
					if err := vtr.Recover(); err != nil {
						logger.Trace("value transfer recovery is failed", "err", err)
					}
				}
			}
		}
	}()
```

**File:** node/sc/vt_recovery.go (L382-413)
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
}
```
