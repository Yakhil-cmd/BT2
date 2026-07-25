### Title
Malicious `_to` Recipient Permanently Locks KAIA and Stalls Bridge Handle-Nonce — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` uses a push-strategy to deliver KAIA to the bridge recipient `_to`. If `_to` is a contract whose fallback always reverts, the entire operator transaction reverts (including all nonce-state updates), the nonce can never be marked as handled, and there is no admin escape hatch to skip it. The result is permanent lock of the originating user's KAIA on the parent chain and a permanently stalled `lowerHandleNonce` that breaks the bridge's sequential-nonce invariant and recovery mechanism.

---

### Finding Description

`handleKLAYTransfer` performs all state mutations — closing the vote, recording `handleNoncesToBlockNums`, advancing `lowerHandleNonce` — and then pushes KAIA to `_to` as the very last step:

```solidity
// BridgeTransferKLAY.sol lines 81-99
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);

emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");   // ← reverts entire tx on failure
``` [1](#0-0) 

Because `require(ok, ...)` reverts the entire transaction, every state change above it is also rolled back. The vote (`closedValueTransferVotes[nonce]`) is un-closed, `handleNoncesToBlockNums[nonce]` is zeroed, and `lowerHandleNonce` is unchanged. Operators can retry, but if `_to` is a contract that unconditionally reverts, every retry fails identically.

`_updateHandleNonce` advances `lowerHandleNonce` only when `handleNoncesToBlockNums[i] > 0` for consecutive nonces:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
``` [2](#0-1) 

Because nonce N is never successfully written, `lowerHandleNonce` is permanently stuck at N and `recoveryBlockNumber` is frozen at the block preceding N. There is no owner-callable function to skip a nonce or force-advance `lowerHandleNonce`.

On the request side, `_requestKLAYTransfer` increments `requestNonce` and emits the event but provides no cancel path:

```solidity
requestNonce++;
``` [3](#0-2) 

The parent-chain KAIA is locked in the parent bridge with no refund mechanism.

---

### Impact Explanation

| Asset | Effect |
|---|---|
| User's KAIA on parent chain | Permanently locked — no cancel/refund function exists |
| Child-chain bridge KAIA pool | The corresponding amount can never be disbursed for nonce N |
| `lowerHandleNonce` | Permanently frozen; `recoveryBlockNumber` is stale |
| Bridge recovery daemon | Continuously re-scans from the frozen block, never making progress on nonce N |

While nonces > N can still be individually handled (the `_lowerHandleNonceCheck` only requires `lowerHandleNonce <= _requestedNonce`), `lowerHandleNonce` never advances past N, so the sequential-nonce invariant and the recovery mechanism are permanently broken for the affected bridge instance. [4](#0-3) 

---

### Likelihood Explanation

The trigger is fully unprivileged. Any user on the parent chain can call `requestKLAYTransfer` and supply an arbitrary `_to` address:

```solidity
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
``` [5](#0-4) 

The attacker deploys a contract on the child chain whose fallback unconditionally reverts, then bridges any non-zero KAIA amount to it. The cost is the bridged KAIA plus gas. No operator cooperation or privileged access is required.

---

### Recommendation

1. **Pull-pattern for delivery**: Do not `require` the push to succeed. Instead, record the owed amount in a mapping and let the recipient claim it separately (analogous to how `cancelTransfer` is implemented per-bidder in the reference report).
2. **Nonce-skip escape hatch**: Add an `onlyOwner` function that can mark a nonce as permanently failed and advance `lowerHandleNonce`, so the bridge is not permanently stalled by a single bad recipient.
3. **Limit return-data size**: If the push-strategy is retained, use a gas-capped call (e.g., `call{value: _value, gas: 2300}`) to prevent gas-bomb griefing, and emit a failure event rather than reverting.

---

### Proof of Concept

```solidity
// Deployed on child chain by attacker
contract RevertOnReceive {
    receive() external payable { revert("no"); }
}
```

1. Attacker deploys `RevertOnReceive` on the child chain at address `0xDEAD`.
2. Attacker calls `parentBridge.requestKLAYTransfer{value: 1 ether}(0xDEAD, 1 ether, "")` on the parent chain. `requestNonce` becomes N; 1 KAIA is locked in the parent bridge.
3. Bridge operators observe the `RequestValueTransfer` event and call `childBridge.handleKLAYTransfer(txHash, attacker, 0xDEAD, 1e18, N, blockNum, "")`.
4. `_to.call.value(1e18)("")` → `RevertOnReceive.receive()` reverts → entire tx reverts.
5. `handleNoncesToBlockNums[N]` remains 0; `lowerHandleNonce` stays at N.
6. Every subsequent operator retry produces the same revert.
7. `lowerHandleNonce` is permanently frozen at N; 1 KAIA on the parent chain is permanently locked with no recovery path.

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L123-123)
```text
        requestNonce++;
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```
