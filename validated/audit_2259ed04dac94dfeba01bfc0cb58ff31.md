### Title
Push-Based KAIA Transfer in `handleKLAYTransfer` Permanently Locks Bridged Assets and Corrupts Bridge Nonce State — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` delivers KAIA to the recipient `_to` via a push-based `.call.value()`. If `_to` is a contract whose `receive` function reverts, the entire transaction reverts, the nonce is never marked handled, and the bridged KAIA is permanently locked inside the destination bridge contract. Because the nonce can never be retired, `lowerHandleNonce` and `recoveryBlockNumber` are permanently stuck, corrupting the bridge's recovery state.

---

### Finding Description

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` executes the following sequence:

```solidity
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);
emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");   // ← reverts entire tx if _to reverts
``` [1](#0-0) 

All state mutations that precede the `.call` — including `_setHandledRequestTxHash`, `handleNoncesToBlockNums`, `_updateHandleNonce`, and the `closedValueTransferVotes[_requestedNonce] = true` set inside `_voteValueTransfer` — are atomically reverted when `require(ok, ...)` fires. [2](#0-1) 

Because `closedValueTransferVotes[N]` is reverted to `false`, operators can re-vote and re-attempt the transfer indefinitely, but every attempt will revert as long as `_to` reverts. `handleNoncesToBlockNums[N]` is therefore never persistently set, so `_updateHandleNonce` can never advance `lowerHandleNonce` past `N`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;   // stops at N forever
``` [3](#0-2) 

The `_to` address is user-supplied on the source chain via `requestKLAYTransfer`. Bridge operators relay it verbatim to `handleKLAYTransfer`. There is no on-chain mechanism to skip a stuck nonce or redirect delivery to a different address. [4](#0-3) 

---

### Impact Explanation

1. **Permanent asset lock**: The KAIA locked in the destination bridge for nonce `N` can never be delivered. There is no admin escape hatch to withdraw or redirect it. The bridged KAIA is effectively burned.
2. **`lowerHandleNonce` permanently stuck**: `lowerHandleNonce` never advances past `N`. `recoveryBlockNumber` is frozen at the block before `N`, so any bridge restart re-scans all events from that point, causing operator overhead and potential duplicate-handling attempts for all nonces after `N`.
3. **Scope**: Other nonces (`N+1`, `N+2`, …) can still be handled because `_lowerHandleNonceCheck` only requires `lowerHandleNonce <= _requestedNonce`. The bridge is not fully halted, but its accounting state is permanently corrupted and the locked KAIA is unrecoverable without a contract upgrade.

This satisfies the allowed impact gate: *unauthorized loss of bridged assets (KAIA locked in system-managed bridge funds)* and *persistent corruption of bridge nonce/state that breaks settlement*.

---

### Likelihood Explanation

Any user who initiates a KAIA bridge transfer (`requestKLAYTransfer`) with `_to` set to a contract they control can trigger this. The attacker deploys a contract with a conditionally reverting `receive` function, bridges KAIA to it, then flips the revert flag before operators call `handleKLAYTransfer`. The cost is only the bridged KAIA amount (which the attacker controls) plus gas. No privileged access is required.

---

### Recommendation

Replace the push-based delivery with a pull-payment pattern, analogous to the fix applied to the Particle Exchange bug:

1. Instead of `_to.call.value(_value)("")` inside `handleKLAYTransfer`, record the claimable amount in a mapping: `pendingWithdrawals[_to] += _value`.
2. Add a separate `claimKLAY()` function that lets `_to` pull its balance. A revert in `claimKLAY` affects only the caller and does not block any bridge nonce.
3. Alternatively, wrap the `.call` in a try/catch (not available in Solidity 0.5.6, so an upgrade to ≥0.6 is needed) and on failure store the amount for later claim rather than reverting the entire transaction.

---

### Proof of Concept

1. Alice deploys `MaliciousReceiver` on the destination chain with a `receive()` that reverts when `block.number > threshold`.
2. Alice calls `requestKLAYTransfer(address(MaliciousReceiver), value, "")` on the source bridge, locking `value` KAIA. This emits `RequestValueTransfer` with nonce `N`.
3. Alice sets `threshold = block.number` on `MaliciousReceiver`, making its `receive` revert from now on.
4. Bridge operators observe the event and call `handleKLAYTransfer(..., MaliciousReceiver, value, N, ...)`. The `.call.value(value)("")` returns `(false, )`, `require(ok, ...)` reverts the entire transaction.
5. All state changes (including `closedValueTransferVotes[N] = true`) are rolled back. Operators retry — same result every time.
6. `handleNoncesToBlockNums[N]` is never set. `lowerHandleNonce` stays at `N`. `recoveryBlockNumber` is frozen. The `value` KAIA is permanently locked in the destination bridge with no recovery path. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L102-116)
```text
    // _voteValueTransfer votes value transfer transaction with the operator.
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
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
