### Title
Malicious `_to` recipient can permanently lock KAIA in the service-chain bridge — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` sends KAIA to a user-supplied `_to` address via a low-level `.call.value()` and then hard-reverts if the call fails. Because all nonce-state mutations happen before the transfer, a revert rolls back every state change, leaving the nonce permanently unhandled. Any user who specifies a reverting contract as `_to` on the source chain can permanently lock the corresponding KAIA in the destination bridge with no recovery path.

---

### Finding Description

`handleKLAYTransfer` in `BridgeTransferKLAY` executes the following sequence:

1. `_lowerHandleNonceCheck` — gate check
2. `_voteValueTransfer` — sets `closedValueTransferVotes[nonce] = true`
3. `_setHandledRequestTxHash` — marks the request tx hash
4. `handleNoncesToBlockNums[nonce] = blockNumber`
5. `_updateHandleNonce` — advances `lowerHandleNonce`
6. `emit HandleValueTransfer`
7. `(bool ok,) = _to.call.value(_value)("")` — sends KAIA to `_to`
8. `require(ok, "handleKLAYTransfer: transfer failed")` — **reverts entire tx if transfer fails** [1](#0-0) 

Because Solidity reverts are atomic, steps 2–6 are all rolled back when step 8 fires. The nonce is never marked handled, `lowerHandleNonce` never advances, and the KAIA sitting in the bridge contract can never be delivered to `_to`.

The `_to` address originates directly from the user's `requestKLAYTransfer` call on the source chain: [2](#0-1) 

There is no skip-nonce, emergency-withdraw, or override mechanism in the bridge contract. The `setFeeReceiver` and `setRunningStatus` owner functions cannot unblock a stuck nonce. [3](#0-2) 

The `lowerHandleNonce` advancement loop in `_updateHandleNonce` requires `handleNoncesToBlockNums[i] > 0` for every consecutive nonce starting from `lowerHandleNonce`. Because the stuck nonce's entry is never written (always reverted), the loop halts immediately and `lowerHandleNonce` is frozen: [4](#0-3) 

---

### Impact Explanation

- **Unauthorized asset lock**: KAIA deposited into the source-chain bridge (locked or burned on `RequestValueTransfer`) is permanently stranded in the destination bridge. The user's funds are consumed on the source side but never delivered on the destination side.
- **Bridge nonce state corruption**: `lowerHandleNonce` and `recoveryBlockNumber` are frozen at the stuck nonce. The bridge recovery mechanism re-scans from `recoveryBlockNumber`, causing repeated failed handle attempts and operator gas drain. Future nonces can still be voted on but `lowerHandleNonce` never advances past the stuck one, so the nonce window is permanently skewed.

---

### Likelihood Explanation

Any unprivileged user can trigger this by calling `requestKLAYTransfer` on the source chain with `_to` set to a contract whose `receive()` or fallback reverts. No special role, key, or majority-validator collusion is required. The cost to the attacker is only the bridged KAIA amount plus gas.

---

### Recommendation

Move the KAIA transfer **before** any state mutations, or — preferably — adopt a pull-payment pattern: record the owed amount in a mapping and let `_to` withdraw it separately. If push-delivery must be retained, catch a failed transfer without reverting and emit an event so operators can escalate or the owner can redirect funds:

```solidity
(bool ok, ) = _to.call.value(_value)("");
if (!ok) {
    pendingWithdrawals[_to] += _value;
    emit KLAYTransferFailed(_requestTxHash, _to, _value);
    return;
}
```

This mirrors the recommendation in the external report (Option 1): do not revert on a failed fee/value transfer; instead emit an event and allow recovery.

---

### Proof of Concept

```solidity
// MaliciousRecipient.sol
contract MaliciousRecipient {
    receive() external payable { revert(); }
}

// Attack scenario (Hardhat/Foundry test)
function test_handleKLAYTransferDOS() public {
    MaliciousRecipient bad = new MaliciousRecipient();

    // 1. User requests KLAY transfer on source chain specifying bad as _to
    //    (source bridge emits RequestValueTransfer with to = address(bad))

    // 2. Bridge operators attempt to handle on destination chain
    vm.expectRevert("handleKLAYTransfer: transfer failed");
    bridge.handleKLAYTransfer(
        txHash, from, payable(address(bad)), 1 ether,
        requestNonce, blockNum, ""
    );

    // 3. lowerHandleNonce is unchanged; KAIA locked in bridge forever
    assertEq(bridge.lowerHandleNonce(), 0);
}
``` [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L149-155)
```text
        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L162-168)
```text
    // setFeeReceivers sets fee receiver.
    function setFeeReceiver(address payable _feeReceiver)
        external
        onlyOwner
    {
        _setFeeReceiver(_feeReceiver);
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L43-66)
```text
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfKLAY;

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            (bool ok, ) = feeReceiver.call.value(fee)("");
            require(ok, "transfer fee failed");

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                (bool ok, ) = msg.sender.call.value(feeRefund)("");
                require(ok, "refund fee failed");
            }

            return fee;
        }

        if (_feeLimit > 0) {
            (bool ok, ) = msg.sender.call.value(_feeLimit)("");
            require(ok, "refund fee failed");
        }
        return 0;
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
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
