### Title
Malicious or Reverting `_to` Contract Permanently Locks KAIA in Bridge — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` delivers bridged KAIA to the recipient via a low-level `call`. If the recipient address is a contract whose fallback/receive function reverts, the entire transaction reverts (including all nonce-state updates), the nonce is never consumed, and the KAIA is permanently locked inside the bridge contract with no on-chain recovery path.

### Finding Description

`handleKLAYTransfer` performs all nonce-state mutations before the external call to `_to`:

```
_setHandledRequestTxHash(_requestTxHash);          // line 81
handleNoncesToBlockNums[_requestedNonce] = ...;    // line 83
_updateHandleNonce(_requestedNonce);               // line 84
emit HandleValueTransfer(...);                     // line 86-96

(bool ok, ) = _to.call.value(_value)("");          // line 98
require(ok, "handleKLAYTransfer: transfer failed");// line 99
``` [1](#0-0) 

Because Solidity reverts the entire call frame on `require(ok, ...)`, every state write on lines 81–84 is rolled back. The nonce is never marked handled, `lowerHandleNonce` never advances past this slot, and the KAIA remains in the bridge contract.

The off-chain bridge manager (`BridgeInfo.handleRequestValueTransferEvent`) will keep re-submitting the handle transaction on every recovery cycle: [2](#0-1) 

Each retry reverts identically, so the KAIA is irrecoverable.

### Impact Explanation

- **Permanent KAIA lockup**: KAIA locked on the source chain is never released on the destination chain. The user's funds are destroyed.
- **Infinite gas drain**: The value-transfer recovery loop (`vt_recovery.go`) retries the stuck nonce indefinitely, consuming bridge-operator gas with no progress.
- **Nonce window stall**: `lowerHandleNonce` cannot advance past the stuck nonce. After 200 subsequent nonces are handled, `_updateHandleNonce`'s inner loop stalls at the stuck slot on every future call, adding O(1) wasted iterations to every subsequent handle transaction. [3](#0-2) 

### Likelihood Explanation

Any user who initiates a KLAY transfer on the source chain and specifies a contract address as `_to` that reverts on receiving native tokens triggers this path. Concrete cases:

1. The user intentionally or accidentally targets a contract with no `receive`/`payable fallback`.
2. A front-runner deploys a reverting contract at the target address (via CREATE2) between the source-chain request and the destination-chain handle.
3. The target contract conditionally reverts (e.g., a multisig or DAO contract that is paused or has been upgraded to reject incoming KAIA).

No privileged role is required; any bridge user can trigger this.

### Recommendation

Apply a pull-payment pattern for KAIA delivery: instead of pushing KAIA to `_to` inside `handleKLAYTransfer`, credit the amount to a per-address claimable balance and let `_to` withdraw it separately. This decouples nonce advancement from the recipient's ability to receive native tokens, mirroring the mitigation recommended in the original report ("send tokens to the vault first; the owner claims later").

Alternatively, if push delivery is retained, catch the failure without reverting the nonce state:

```solidity
(bool ok, ) = _to.call.value(_value)("");
if (!ok) {
    pendingWithdrawals[_to] += _value;  // claimable later
}
```

This ensures the bridge nonce always advances and KAIA is never permanently locked.

### Proof of Concept

1. Deploy a contract `MaliciousReceiver` on the destination chain whose `receive()` always reverts.
2. On the source chain, call `requestKLAYTransfer(maliciousReceiverAddr, value, "")` with `msg.value = value`.
3. Bridge operators observe the `RequestValueTransfer` event and call `handleKLAYTransfer(..., maliciousReceiverAddr, value, ...)` on the destination bridge.
4. `_to.call.value(_value)("")` returns `ok = false`; `require` reverts the transaction.
5. Observe: `lowerHandleNonce` is unchanged, `handleNoncesToBlockNums[nonce] == 0`, bridge KAIA balance is unchanged.
6. The recovery module re-submits the same call; it reverts again. The KAIA is permanently locked. [4](#0-3) [5](#0-4)

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

**File:** node/sc/bridge_manager.go (L332-337)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-156)
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
