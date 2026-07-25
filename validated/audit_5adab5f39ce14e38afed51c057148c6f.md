### Title
KLAY Permanently Locked in Bridge When `_to` Is a Non-Payable Contract — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` delivers bridged KLAY via a low-level `.call.value()` and hard-reverts if the call fails. Because the `_to` address is fixed at request time and the operator vote key is `keccak256(msg.data)`, operators can never redirect the transfer. If `_to` is a contract that rejects KLAY (no payable fallback, explicit `revert`, or a proxy later upgraded to reject), the KLAY is permanently locked inside the destination bridge contract with no recovery path.

---

### Finding Description

`requestKLAYTransfer` on the source bridge accepts any `_to` address without validation and emits it in a `RequestValueTransfer` event: [1](#0-0) 

Bridge operators observe that event and call `handleKLAYTransfer` on the destination bridge, passing the same `_to`. After the operator threshold is reached and all nonce bookkeeping is written, the contract attempts delivery: [2](#0-1) 

If `_to.call.value(_value)("")` returns `false` (contract has no payable fallback, or explicitly reverts), the `require` causes the entire transaction to revert. Because the vote key is `keccak256(msg.data)`, operators cannot change `_to` without producing a different key that will never reach threshold — they are permanently stuck replaying the same failing call.

The `_voteValueTransfer` guard only blocks re-entry once `closedValueTransferVotes[nonce]` is set, but that flag is also reverted on failure, so operators can keep calling — and keep failing — indefinitely: [3](#0-2) 

There is no escape hatch: no admin function to redirect a stuck transfer, no expiry after which the user can reclaim funds, and no fallback that credits the bridge owner.

A secondary, related surface exists in `BridgeFee._payKLAYFeeAndRefundChange`: if `feeReceiver` is set to a contract that reverts on KLAY receipt, every `requestKLAYTransfer` call on the source side will revert, causing a full DoS on KLAY bridging (though this path requires the bridge owner to set a bad `feeReceiver`): [4](#0-3) 

---

### Impact Explanation

KLAY sent by a user on the source chain is locked in the destination bridge contract with no recovery mechanism. The exact corrupted value is the full `_value` amount of KLAY that was deposited into the source bridge and can never be delivered or refunded. This is an unauthorized permanent loss of bridged assets — matching the "unauthorized transfer/unlock/burn affecting bridged assets" impact gate.

---

### Likelihood Explanation

The trigger is any `_to` address that is a contract without a payable fallback. This includes:

1. A user who accidentally specifies a contract address (e.g., a multisig, DAO, or DeFi vault) that does not accept raw KLAY.
2. A `_to` contract that was a valid receiver at request time but was later upgraded (via a proxy) to reject KLAY — a realistic scenario given the time gap between request and handle.
3. A malicious actor who intentionally bridges KLAY to a self-deployed revert contract to grief the bridge's nonce window (the 200-nonce sliding window in `_updateHandleNonce` means a stuck nonce can block `lowerHandleNonce` advancement).

No privileged access is required; any user of `requestKLAYTransfer` can trigger this.

---

### Recommendation

1. **Pull pattern**: Instead of pushing KLAY to `_to` in `handleKLAYTransfer`, credit a `pendingWithdrawals[_to]` mapping and let recipients pull their funds. This eliminates the revert-on-receive failure mode entirely.
2. **Fallback recipient**: If the push fails, credit the KLAY to a recoverable escrow (e.g., the bridge owner or the original `_from` address) rather than reverting.
3. **Source-side validation**: In `requestKLAYTransfer`, reject `_to` addresses that are known to be contracts without payable fallbacks (limited, but reduces accidental cases).
4. **Admin recovery function**: Add an owner-only function to redirect a stuck nonce's KLAY to an alternate address after a timeout.

---

### Proof of Concept

1. Deploy a contract `Rejecter` with no payable fallback (or `receive() external payable { revert(); }`).
2. Call `requestKLAYTransfer(address(Rejecter), 1 ether, "")` on the source bridge with `msg.value = 1 ether`. The source bridge locks 1 KAIA and emits `RequestValueTransfer` with `to = address(Rejecter)`.
3. Bridge operators call `handleKLAYTransfer(txHash, from, address(Rejecter), 1 ether, nonce, blockNum, "")` on the destination bridge. Once threshold votes are cast, the contract executes `address(Rejecter).call.value(1 ether)("")` → returns `false` → `require` reverts the entire transaction.
4. All state changes (nonce bookkeeping, `closedValueTransferVotes`) are rolled back. Operators retry — same result every time.
5. The destination bridge holds 1 KAIA permanently. The user's 1 KAIA on the source chain is already gone. No function exists to recover it. [5](#0-4) [1](#0-0) [6](#0-5)

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

**File:** contracts/service_chain/bridge/BridgeFee.sol (L46-50)
```text
        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            (bool ok, ) = feeReceiver.call.value(fee)("");
            require(ok, "transfer fee failed");
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
