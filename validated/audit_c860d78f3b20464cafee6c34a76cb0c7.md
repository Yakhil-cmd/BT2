### Title
KAIA Permanently Locked in Service-Chain Bridge When Recipient Contract Has No Fallback — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary
`handleKLAYTransfer` in the service-chain bridge transfers native KAIA to an arbitrary `_to` address using a raw `.call.value()`. If `_to` is a smart contract without a `receive`/`fallback` function, the call returns `ok = false`, the `require` reverts the entire transaction, and the nonce is never consumed. Because the bridge has no alternative delivery path and no skip/recovery mechanism for permanently-undeliverable nonces, the KAIA locked in the bridge for that cross-chain request is irrecoverable.

### Finding Description

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` performs all state mutations (marks the request-tx hash as handled, writes `handleNoncesToBlockNums`, advances `_updateHandleNonce`) and then attempts the native transfer:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [1](#0-0) 

Because the `require` is the last statement, a revert rolls back every state change in the same call. The nonce is therefore never marked consumed, and bridge operators can retry indefinitely — but every retry will revert for the same reason. There is no wrapped-KAIA fallback, no operator-callable skip function, and no emergency-withdrawal path in the contract.

The `_to` address originates from the user's `requestKLAYTransfer` call on the source chain:

```solidity
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
``` [2](#0-1) 

Once the `RequestValueTransfer` event is emitted on the source chain, the source-side KAIA is already deducted from the user. The destination bridge holds the corresponding KAIA but can never deliver it.

The `lowerHandleNonce` cannot advance past the stuck nonce because `_updateHandleNonce` scans forward from `lowerHandleNonce` only through entries that have been written to `handleNoncesToBlockNums`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
``` [3](#0-2) 

Since the stuck nonce's entry is always reverted, `lowerHandleNonce` is permanently blocked, and `recoveryBlockNumber` cannot advance, degrading the bridge's recovery subsystem.

### Impact Explanation

- **Bridged KAIA is permanently locked.** The user's KAIA on the source chain is consumed; the destination bridge holds the equivalent amount but has no mechanism to deliver or refund it.
- **`lowerHandleNonce` is permanently blocked** at the stuck nonce, preventing the recovery-block-number from advancing and degrading the value-transfer recovery system for all subsequent transfers.
- The bridge contract is not upgradeable and has no `emergencyWithdraw` or nonce-skip function, making the loss irreversible.

### Likelihood Explanation

Smart contracts routinely bridge assets to other smart contracts (e.g., multisigs, vaults, protocol treasuries). A contract that holds KAIA on the source chain but whose counterpart on the destination chain lacks a `receive`/`fallback` function is a realistic deployment pattern. The bridge emits no warning and performs no pre-flight check on `_to`'s ability to accept native KAIA. Any user who bridges to such an address triggers the condition without any privileged action.

### Recommendation

1. **Add a WKAIA fallback.** Mirror the ETH/WETH pattern: if the raw KAIA transfer to `_to` fails, wrap the amount into WKAIA and transfer the ERC-20 token instead. This ensures funds are always deliverable.
2. **Alternatively, validate `_to` at request time.** On the source chain, reject `requestKLAYTransfer` calls where `_to` is a contract address (or require an explicit opt-in flag).
3. **Add an operator-callable nonce-skip / emergency-refund function** so that a permanently-stuck nonce can be resolved without bricking the bridge.

### Proof of Concept

1. Deploy `BridgeTransferKLAY` on a simulated chain and fund it with 10 KAIA.
2. Deploy a contract `NoFallback` with no `receive` or `fallback` function.
3. Call `handleKLAYTransfer(txHash, alice, address(NoFallback), 1 ether, 0, blockNum, "")` as an operator.
4. Observe: transaction reverts with `"handleKLAYTransfer: transfer failed"`.
5. Observe: `lowerHandleNonce` remains `0`; `handleNoncesToBlockNums[0]` remains `0`.
6. Repeat step 3 indefinitely — every attempt reverts.
7. Observe: the 1 KAIA is permanently locked in the bridge; `lowerHandleNonce` never advances. [4](#0-3) [5](#0-4)

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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L150-155)
```text
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
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
