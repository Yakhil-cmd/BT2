### Title
Malicious `_to` receiver permanently locks bridged KLAY via forced revert in `handleKLAYTransfer` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` delivers bridged KLAY to the user-supplied `_to` address via a low-level call and then unconditionally requires the call to succeed. If `_to` is a contract that always reverts, every operator attempt to settle that nonce fails, the nonce is never consumed, and the corresponding KLAY is permanently locked inside the bridge contract. The user who initiated the transfer on the source chain has already had their KLAY locked or burned; the destination bridge holds the funds but can never release them.

---

### Finding Description

`handleKLAYTransfer` follows this sequence:

1. Validates the nonce (`_lowerHandleNonceCheck`)
2. Collects operator votes (`_voteValueTransfer`) — sets `closedValueTransferVotes[nonce] = true` only on success
3. Updates bridge state: `_setHandledRequestTxHash`, `handleNoncesToBlockNums[nonce]`, `_updateHandleNonce`
4. Emits `HandleValueTransfer`
5. Calls `_to` with the KLAY value
6. **`require(ok, "handleKLAYTransfer: transfer failed")`** [1](#0-0) 

Because step 6 is a hard `require`, any revert from `_to` causes the entire transaction to revert — including all state mutations from steps 2–4. The result is:

- `closedValueTransferVotes[nonce]` is **not** set, so operators can retry indefinitely, but every attempt reverts.
- `handleNoncesToBlockNums[nonce]` is **not** written, so `_updateHandleNonce` can never advance `lowerHandleNonce` past this nonce.
- `recoveryBlockNumber` is stuck at the block before the poisoned nonce, degrading the value-transfer recovery mechanism.
- The KLAY is held by the bridge contract with no path to delivery or refund.

The `_to` address is fully user-controlled: it is passed directly from `requestKLAYTransfer` on the source chain. [2](#0-1) 

`_lowerHandleNonceCheck` only enforces `lowerHandleNonce <= _requestedNonce`, so other nonces can still be processed out of order, but `lowerHandleNonce` will never advance past the stuck nonce. [3](#0-2) 

`_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive `i` starting from `lowerHandleNonce`. A gap at the poisoned nonce permanently halts this advancement. [4](#0-3) 

---

### Impact Explanation

**Unauthorized permanent lock of bridged KLAY assets.** The user's KLAY on the source chain is already consumed (locked in the source bridge or burned under `modeMintBurn`). The destination bridge holds the corresponding KLAY but can never deliver it. This satisfies the allowed-impact gate: *unauthorized lock of bridged assets affecting system-managed funds*.

Additionally, `lowerHandleNonce` and `recoveryBlockNumber` are permanently corrupted for the affected bridge pair, breaking the canonical recovery path for all subsequent nonces that depend on sequential advancement.

---

### Likelihood Explanation

Any user who initiates a KLAY transfer via `requestKLAYTransfer` can set `_to` to a contract they control that unconditionally reverts. No special privilege is required. The attack is cheap (one source-chain transaction) and irreversible without a bridge contract upgrade or owner intervention. The bridge operator has no on-chain mechanism to skip or override a stuck nonce.

---

### Recommendation

Replace the push-delivery pattern with a **pull-payment** pattern:

```solidity
// Instead of:
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");

// Use:
pendingWithdrawals[_to] += _value;
// Provide a separate withdraw() function for recipients to claim their KLAY.
```

Alternatively, handle delivery failure gracefully without reverting — log the failure and store the amount for later manual recovery — so the nonce is always consumed and `lowerHandleNonce` can advance regardless of `_to`'s behavior.

---

### Proof of Concept

1. Attacker deploys a contract `MaliciousReceiver` on the destination chain whose fallback function always executes `revert()`.
2. Attacker calls `requestKLAYTransfer(address(MaliciousReceiver), value, "")` on the source bridge, paying `value` KLAY. The source bridge locks/burns the KLAY and emits `RequestValueTransfer` with nonce N.
3. The bridge operator observes the event and calls `handleKLAYTransfer(..., address(MaliciousReceiver), value, N, ...)` on the destination bridge.
4. The destination bridge executes steps 1–4 (state updates, event), then calls `MaliciousReceiver.fallback()` which reverts.
5. `require(ok, ...)` causes the entire transaction to revert. All state updates are rolled back.
6. `closedValueTransferVotes[N]` remains `false`; operators can retry but every attempt reverts identically.
7. `handleNoncesToBlockNums[N]` is never written; `lowerHandleNonce` is permanently stuck at N.
8. The `value` KLAY is locked in the destination bridge contract with no delivery or refund path. [5](#0-4) [6](#0-5)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-134)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-160)
```text
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
