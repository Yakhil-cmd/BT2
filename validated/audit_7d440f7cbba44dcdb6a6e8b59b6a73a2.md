### Title
Reverting `_to` in `handleKLAYTransfer` permanently locks bridged KAIA and griefs bridge operators — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` delivers KAIA to the user-controlled `_to` address via a raw `.call.value()` and immediately `require`s success. If `_to` is a contract that reverts on receiving KAIA, the entire transaction reverts, rolling back every state mutation that preceded the call. The nonce is never consumed, the KAIA remains locked in the source bridge forever, and the bridge operator loses gas on every retry.

---

### Finding Description

`handleKLAYTransfer` performs all critical state updates — marking the request-tx hash as handled, recording the nonce-to-block mapping, and advancing `lowerHandleNonce` — **before** the external KAIA transfer:

```solidity
_setHandledRequestTxHash(_requestTxHash);          // handledRequestTx[hash] = true
handleNoncesToBlockNums[_requestedNonce] = ...;    // nonce recorded
_updateHandleNonce(_requestedNonce);               // lowerHandleNonce advanced

emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");          // ← external call to user-controlled address
require(ok, "handleKLAYTransfer: transfer failed"); // ← reverts entire tx on failure
``` [1](#0-0) 

Because Solidity reverts roll back all state changes atomically, every mutation above is undone when `_to` reverts. The result:

- `handledRequestTx[_requestTxHash]` is **not** set.
- `handleNoncesToBlockNums[_requestedNonce]` is **not** set.
- `lowerHandleNonce` is **not** advanced.

`_lowerHandleNonceCheck` only enforces `lowerHandleNonce <= _requestedNonce`: [2](#0-1) 

So the stuck nonce does not block later nonces from being processed, but `lowerHandleNonce` never advances past it. `_updateHandleNonce` scans forward from `lowerHandleNonce` and stops the moment it finds a gap: [3](#0-2) 

Consequently `recoveryBlockNumber` is permanently frozen at its initial value, and the value-transfer recovery subsystem (`vt_recovery`) will re-scan from the genesis block on every cycle, compounding the operator's cost.

---

### Impact Explanation

1. **Permanent KAIA lock**: The user's KAIA is held in the source bridge after `requestKLAYTransfer`. There is no refund path. If `handleKLAYTransfer` can never succeed, those funds are irrecoverable.
2. **Bridge operator gas drain**: Every retry by every operator (including multi-sig threshold re-votes via `_voteValueTransfer`) costs gas with zero progress.
3. **`recoveryBlockNumber` frozen**: The value-transfer recovery module uses `recoveryBlockNumber` to bound its log scan. With it stuck at `1`, recovery rescans the entire chain history on every invocation. [4](#0-3) 

---

### Likelihood Explanation

The `_to` address is chosen by the user on the **source** chain and is embedded in the `RequestValueTransfer` event that operators replay. Any user can:

- Accidentally send to a multisig or proxy contract that has no `receive()` function.
- Deliberately deploy a contract whose `receive()` reverts unconditionally, or reverts only when called by the bridge operator (honeypot pattern: simulated calls succeed, on-chain calls revert).

No special privilege is required. The source-chain `requestKLAYTransfer` is open to any caller. [5](#0-4) 

---

### Recommendation

Decouple the KAIA delivery from the nonce-accounting state update. Two options:

1. **Fallback address**: If `_to.call.value(_value)("")` fails, send the KAIA to a designated recovery address (e.g., the bridge owner) and emit a `HandleValueTransferFailed` event, so the nonce is still consumed and `lowerHandleNonce` advances.
2. **Pull pattern**: Credit `_to` in a claimable balance mapping instead of pushing KAIA directly; let the recipient pull it. This eliminates the revert vector entirely.

Either approach ensures the nonce is consumed regardless of the recipient's behaviour, matching the intent of `_setHandledRequestTxHash` and `_updateHandleNonce`.

---

### Proof of Concept

```solidity
// 1. Attacker deploys a reverting receiver on the destination chain
contract RevertOnReceive {
    receive() external payable { revert("no KAIA"); }
}

// 2. On the source chain, attacker calls:
sourceBridge.requestKLAYTransfer{value: 10 ether}(
    address(revertOnReceive), // _to
    10 ether,
    ""
);
// → KAIA locked in source bridge, RequestValueTransfer(nonce=N) emitted

// 3. Bridge operator calls on destination chain:
destBridge.handleKLAYTransfer(
    requestTxHash, from, address(revertOnReceive),
    10 ether, N, blockNum, ""
);
// → _to.call.value(10 ether)("") reverts
// → require(ok) reverts entire tx
// → ALL state rolled back: handledRequestTx, handleNoncesToBlockNums, lowerHandleNonce
// → Operator loses gas, nonce N unprocessed, 10 KAIA permanently locked
``` [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```
