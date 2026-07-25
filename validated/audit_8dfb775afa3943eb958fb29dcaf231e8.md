### Title
Malicious Recipient Contract Permanently Freezes Bridge KAIA Transfer and Stalls `lowerHandleNonce` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` sends native KAIA to a caller-supplied `_to` address using a low-level `call.value()` and hard-requires the call to succeed. A user who initiates a cross-chain KAIA transfer on the parent chain can set `_to` to a contract whose `receive()` always reverts. Every bridge-operator attempt to settle that nonce will revert, permanently locking the KAIA in the child-chain bridge and freezing `lowerHandleNonce` at that nonce forever.

### Finding Description

In `handleKLAYTransfer`:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [1](#0-0) 

The `_to` address originates from the `RequestValueTransfer` event emitted on the parent chain when a user calls `requestKLAYTransfer`. Any user can set `_to` to an arbitrary address, including a contract whose `receive()` unconditionally reverts.

Because the `require(ok, ...)` is placed **after** all state-mutating steps (`_setHandledRequestTxHash`, `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber`, `_updateHandleNonce`), a revert rolls back every state change, including the operator's vote recorded in `_voteValueTransfer`. The nonce is therefore never marked as handled. [2](#0-1) 

`_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive nonces starting from `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
``` [3](#0-2) 

Because the stuck nonce's entry is never written (every tx reverts), `lowerHandleNonce` is permanently anchored at that nonce. There is no owner-callable function to skip or override a stuck nonce. [4](#0-3) 

### Impact Explanation

1. **Permanent KAIA lock**: The KAIA deposited on the parent-chain bridge for the stuck nonce can never be delivered. The child-chain bridge's KAIA reserve for that transfer is also permanently undeliverable.
2. **`lowerHandleNonce` frozen**: `recoveryBlockNumber` never advances past the stuck nonce's block. The bridge recovery mechanism (`recoveryBlockNumber`) is permanently impaired — it will always re-scan from the same block, causing redundant event processing.
3. **Operator gas drain**: Each retry by bridge operators (requiring threshold votes) wastes gas with no possibility of success.
4. **No admin escape hatch**: The contract has no function to manually advance `lowerHandleNonce` or mark a nonce as skipped. [5](#0-4) 

### Likelihood Explanation

The trigger is a single unprivileged `requestKLAYTransfer` call on the parent chain with `_to` set to a contract that reverts on `receive()`. The attacker sacrifices the KAIA they deposit (it is locked in the parent bridge), but the cost is bounded by the minimum transfer amount. The bridge has no mechanism to detect or prevent this at request time. [6](#0-5) 

### Recommendation

Replace the hard-require pattern with a pull-payment or try/catch approach:

1. **Pull-payment**: Instead of pushing KAIA to `_to`, credit the amount to a claimable balance mapping. `_to` calls a separate `claim()` function to withdraw.
2. **Soft failure with skip**: If `_to.call.value(_value)("")` fails, emit a `TransferFailed` event, mark the nonce as handled anyway (so `lowerHandleNonce` can advance), and hold the KAIA in a recoverable escrow mapping keyed by nonce.
3. **Bounded gas forwarding**: Forward a fixed gas stipend to `_to` so a malicious `receive()` cannot consume unlimited gas, though this alone does not prevent the revert.

### Proof of Concept

1. Deploy a malicious contract on the child chain:
   ```solidity
   contract MaliciousReceiver {
       receive() external payable { revert("grief"); }
   }
   ```
2. On the parent chain, call `requestKLAYTransfer(maliciousReceiverAddress, value, "0x")` with `msg.value = value + fee`.
3. Bridge operators observe the `RequestValueTransfer` event and call `handleKLAYTransfer(..., maliciousReceiverAddress, ...)` on the child chain.
4. The `_to.call.value(_value)("")` call fails; `require(ok, ...)` reverts the entire transaction.
5. All state changes (vote, nonce mapping, `lowerHandleNonce`) are rolled back.
6. Every subsequent operator retry reverts identically.
7. `lowerHandleNonce` remains frozen at the stuck nonce; `recoveryBlockNumber` never advances. [7](#0-6) [8](#0-7)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L31-34)
```text
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
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

**File:** contracts/service_chain/bridge/BridgeFee.sol (L43-65)
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
```
