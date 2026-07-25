### Title
KAIA Permanently Stuck in Bridge When Recipient Contract Reverts on Receive — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` sends KAIA to `_to` via a low-level `.call.value()` and then `require`s success. If `_to` is a contract that reverts on receiving KAIA (no `receive`/`fallback`, or an explicit revert), every operator attempt to settle that bridge nonce will revert. The KAIA is permanently locked in the bridge contract with no emergency-withdrawal path.

---

### Finding Description

In `BridgeTransferKLAY.sol`, `handleKLAYTransfer` executes the following sequence: [1](#0-0) 

1. **Line 75** – nonce range check (`_lowerHandleNonceCheck`)
2. **Lines 77-79** – operator vote (`_voteValueTransfer`); returns early if threshold not yet met
3. **Lines 81-84** – marks the request tx hash as handled, records block number, updates nonce tracking
4. **Lines 86-96** – emits `HandleValueTransfer`
5. **Line 98** – `(bool ok, ) = _to.call.value(_value)("")`
6. **Line 99** – `require(ok, "handleKLAYTransfer: transfer failed")`

Because `require(ok)` is the **last** statement, a revert at line 99 rolls back **all** state changes from steps 3-4 (the nonce update, the tx-hash mark, and the vote). The transaction is as if it never happened.

If `_to` is a contract that cannot accept KAIA (e.g., a contract with no `receive`/`fallback`, or one that explicitly reverts), every operator call to `handleKLAYTransfer` for that nonce will revert. The nonce is never consumed, `handleNoncesToBlockNums[_requestedNonce]` is never set, and `lowerHandleNonce` can never advance past that nonce: [2](#0-1) 

The loop in `_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive `i`. A permanently-failing nonce creates a gap that freezes `lowerHandleNonce` at that position indefinitely.

There is no owner-callable rescue or redirect function in the bridge. `chargeWithoutEvent` only adds KAIA; there is no corresponding withdrawal path for stuck funds. [3](#0-2) 

---

### Impact Explanation

- **Stuck KAIA**: The KAIA deposited on the source chain is matched by KAIA held in the destination bridge. Since `handleKLAYTransfer` can never succeed for this nonce, that KAIA is permanently undeliverable and unrecoverable — no emergency-withdrawal function exists.
- **Frozen `lowerHandleNonce`**: The recovery-block-number tracking (`recoveryBlockNumber`) stops advancing for all nonces at or above the stuck one, degrading the bridge's recovery mechanism.
- **Scope**: Affects the service-chain bridge's KAIA transfer path, which is a system-managed fund path within the allowed impact gate (unauthorized lock of bridged assets).

---

### Likelihood Explanation

Any user on the source chain can trigger this by calling `requestKLAYTransfer` and specifying a `_to` address that is a non-payable contract (e.g., a multisig, a DAO contract, or any contract without a `receive` function). This is a realistic, unprivileged action requiring no special role. The user may do so accidentally or deliberately. [4](#0-3) 

---

### Recommendation

1. **Move the KAIA transfer before state updates are finalised, or use a pull-payment pattern**: Record the pending payout in a mapping and let `_to` claim it separately, so a reverting recipient cannot block the nonce.
2. **Add an owner-callable emergency-withdrawal function** that can redirect stuck KAIA to an alternate address (ideally behind a multisig + timelock), analogous to the recommendation in the external report.
3. **Validate `_to` can receive KAIA** on the source-chain request side, or at minimum emit a non-reverting failure event on the destination side and mark the nonce as "failed-but-consumed" so `lowerHandleNonce` can still advance.

---

### Proof of Concept

1. Deploy a non-payable contract `Sink` (no `receive`, no `fallback`) on the destination chain.
2. On the source chain, call `requestKLAYTransfer(Sink, value, extraData)` with `msg.value = value + fee`. The source bridge emits `RequestValueTransfer` with nonce N and holds the KAIA.
3. On the destination chain, operators call `handleKLAYTransfer(..., Sink, value, N, ...)`. The call reaches line 98; `Sink.call.value(value)("")` returns `ok = false`; `require(ok)` reverts the entire transaction.
4. Repeat step 3 with any number of operators — every attempt reverts identically.
5. Observe: `lowerHandleNonce` remains at N; `handleNoncesToBlockNums[N]` is never set; the KAIA in the destination bridge is undeliverable and unrecoverable. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L75-99)
```text
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L137-139)
```text
    // chargeWithoutEvent sends KLAY to this contract without event for increasing
    // the withdrawal limit.
    function chargeWithoutEvent() external payable {}
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
