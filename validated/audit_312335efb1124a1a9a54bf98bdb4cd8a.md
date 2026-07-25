### Title
Recipient-Controlled DoS of KLAY Bridge Delivery Permanently Stalls Bridge Nonce Sequence - (File: contracts/service_chain/bridge/BridgeTransferKLAY.sol)

### Summary
`handleKLAYTransfer` in `BridgeTransferKLAY.sol` delivers bridged KLAY to a user-controlled `_to` address using a low-level call followed by a hard `require`. If `_to` is a contract that reverts on receiving KLAY, every operator attempt to settle that nonce reverts entirely, the nonce is never consumed, `lowerHandleNonce` cannot advance, and all subsequent bridge transfers are permanently blocked.

### Finding Description

`handleKLAYTransfer` performs all state mutations (nonce bookkeeping, event emission) and then attempts the KLAY transfer:

```solidity
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);

emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");   // ← hard revert
``` [1](#0-0) 

Because the `require` is unconditional, a revert from `_to` rolls back the entire transaction, including all nonce state changes. The nonce is therefore never marked as handled. Every subsequent operator call with the same nonce hits the same reverting contract and reverts again. The `lowerHandleNonce` cursor cannot advance past this nonce, so every higher-nonce transfer is also blocked.

The `_to` address originates from the user's `requestKLAYTransfer` call on the source chain:

```solidity
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
``` [2](#0-1) 

Any unprivileged user can supply a `_to` that is a contract with a reverting `receive`/`fallback`.

An identical pattern exists in `BridgeFee._payKLAYFeeAndRefundChange` for the `feeReceiver` and `msg.sender` refund paths:

```solidity
(bool ok, ) = feeReceiver.call.value(fee)("");
require(ok, "transfer fee failed");
``` [3](#0-2) 

If `feeReceiver` is a reverting contract (set by the bridge owner), every `requestKLAYTransfer` call reverts, blocking the request side of the bridge.

### Impact Explanation

- **Permanent bridge nonce stall**: Once a reverting `_to` nonce is submitted, `lowerHandleNonce` is frozen. All subsequent KLAY bridge transfers are undeliverable regardless of their recipients.
- **KAIA locked**: KAIA already locked/burned on the source chain can never be released on the destination chain.
- **No operator recovery path**: Operators cannot skip or override the stuck nonce; the contract provides no mechanism to mark a nonce as permanently failed and advance past it.

### Likelihood Explanation

Any user of the bridge can trigger this by deploying a one-line reverting contract and using it as `_to`. No special privilege is required. The attack is cheap (one bridge request) and permanent.

### Recommendation

1. **`handleKLAYTransfer`**: Do not `require` success on the `_to` transfer. Instead, on failure, store the owed amount in a pull-payment mapping and emit a `TransferFailed` event. The nonce should be consumed regardless of delivery success.
2. **`BridgeFee._payKLAYFeeAndRefundChange`**: Replace `require(ok)` with an event-only failure path for `feeReceiver` and `msg.sender` refund calls, or use a pull-payment pattern.
3. Restrict `returndata` size in the low-level call using inline assembly to prevent gas-inflation attacks.

### Proof of Concept

```solidity
// Attacker deploys this on the destination chain
contract RevertOnReceive {
    receive() external payable { revert("no KLAY"); }
}

// Attacker initiates a bridge transfer on the source chain
bridge.requestKLAYTransfer{value: 1 ether}(
    address(revertOnReceive),  // _to
    1 ether,
    ""
);

// Bridge operators call handleKLAYTransfer on destination chain.
// The call to _to.call.value(1 ether)("") reverts.
// require(ok) reverts the entire tx.
// Nonce N is never consumed.
// lowerHandleNonce stays at N forever.
// All transfers with nonce > N are permanently blocked.
``` [4](#0-3) [5](#0-4)

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
