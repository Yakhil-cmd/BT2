### Title
Bridge KLAY Delivery DoS via Recipient Contract Revert Permanently Locks Bridged KAIA and Stalls `lowerHandleNonce` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in the service-chain bridge delivers KLAY to the recipient `_to` via a low-level `.call.value()` **after** all nonce-accounting state has been written. If `_to` is a contract whose fallback reverts (or consumes all gas), the call returns `ok = false`, the `require` reverts the entire transaction, and every state mutation is rolled back. Because the nonce is never consumed, `lowerHandleNonce` is permanently stuck at that nonce value, the `recoveryBlockNumber` stops advancing, and the bridged KAIA is locked in the contract with no on-chain escape path.

---

### Finding Description

`handleKLAYTransfer` executes in this order:

1. `_lowerHandleNonceCheck` — gate check
2. `_voteValueTransfer` — sets `closedValueTransferVotes[nonce] = true`
3. `_setHandledRequestTxHash` — marks request tx hash as handled
4. `handleNoncesToBlockNums[nonce] = blockNumber` — records block mapping
5. `_updateHandleNonce` — advances `lowerHandleNonce` / `upperHandleNonce`
6. `emit HandleValueTransfer`
7. `(bool ok,) = _to.call.value(_value)("")` — **KLAY push to recipient**
8. `require(ok, "handleKLAYTransfer: transfer failed")` — **reverts entire tx if step 7 fails** [1](#0-0) 

Because Solidity reverts roll back all state changes atomically, steps 2–5 are all undone when step 8 fires. The nonce is never marked handled, `handleNoncesToBlockNums[nonce]` stays `0`, and `_updateHandleNonce` — which advances `lowerHandleNonce` only through a consecutive run of entries where `handleNoncesToBlockNums[i] > 0` — can never advance past this nonce: [2](#0-1) 

`_lowerHandleNonceCheck` only requires `lowerHandleNonce <= _requestedNonce`, so later nonces can still be processed, but `lowerHandleNonce` is permanently frozen at the stuck nonce, and `recoveryBlockNumber` stops advancing: [3](#0-2) 

There is no owner/operator function to skip or override a stuck nonce. The only path to advance `lowerHandleNonce` is a successful `handleKLAYTransfer` for that exact nonce, which is impossible if `_to` always reverts.

The same structural issue exists in `_payKLAYFeeAndRefundChange` on the request side: if `msg.sender` is a reverting contract and a fee refund is owed, the entire `_requestKLAYTransfer` reverts — but that only harms the caller themselves. [4](#0-3) 

---

### Impact Explanation

- **Bridged KAIA permanently locked**: The KLAY held by the bridge contract for nonce N can never be delivered; there is no admin withdrawal path for stuck funds.
- **`lowerHandleNonce` frozen**: `recoveryBlockNumber` stops advancing at the block preceding the stuck nonce. The off-chain `VTRecovery` daemon will perpetually re-submit the failing handle transaction, wasting operator gas and generating noise.
- **Nonce gap accumulation**: If multiple such stuck nonces accumulate, the gap between `lowerHandleNonce` and `upperHandleNonce` grows, increasing the gas cost of every subsequent `_updateHandleNonce` loop.

---

### Likelihood Explanation

Any user who calls `requestKLAYTransfer` (or the fallback) on the service-chain bridge and specifies a `_to` address that is a contract without a payable fallback triggers this condition. This includes:

- Accidental sends to multisig wallets, proxy contracts, or ERC-4337 accounts that do not accept plain KLAY transfers.
- Deliberate griefing: a user deploys a reverting contract at a CREATE2-deterministic address, then requests a transfer to that address; the KLAY is locked and the bridge recovery is stalled.

The trigger requires no special privilege — any caller of `requestKLAYTransfer` on the child chain can set `_to` to an arbitrary address.

---

### Recommendation

Replace the push-transfer pattern with a pull-payment (escrow) model:

1. Instead of `require(ok, ...)` after the call, record the owed amount in a mapping (`pendingWithdrawals[_to] += _value`) and let the recipient claim it separately.
2. Alternatively, check whether `_to` has code (`_to.code.length > 0`) and, if so, attempt the transfer with a fixed gas stipend; on failure, credit an internal escrow rather than reverting.
3. At minimum, replace `require(ok, ...)` with a non-reverting path that stores the undeliverable amount and emits a `TransferFailed` event, so the nonce is still consumed and `lowerHandleNonce` can advance.

---

### Proof of Concept

```
1. Deploy a contract `Rejecter` on the main chain whose fallback always reverts.

2. On the service chain, call:
   bridge.requestKLAYTransfer{value: 1 ether}(Rejecter_address, 1 ether, "");
   → emits RequestValueTransfer(nonce=N, to=Rejecter_address, value=1 ether)

3. Bridge operators observe the event and call on the main-chain bridge:
   bridge.handleKLAYTransfer(txHash, from, Rejecter_address, 1 ether, N, blockNum, "");

4. Execution reaches line 98:
   (bool ok,) = Rejecter_address.call.value(1 ether)("");
   → ok = false (Rejecter reverts)

5. Line 99: require(ok, ...) → entire tx reverts.
   All state (closedValueTransferVotes[N], handleNoncesToBlockNums[N], lowerHandleNonce) rolled back.

6. Operators retry indefinitely; every attempt reverts.
   lowerHandleNonce stays at N.
   recoveryBlockNumber stays at block(N-1).
   1 KAIA is permanently locked in the main-chain bridge contract.
```

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L81-99)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L149-156)
```text
        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L53-56)
```text
            if (feeRefund > 0) {
                (bool ok, ) = msg.sender.call.value(feeRefund)("");
                require(ok, "refund fee failed");
            }
```
