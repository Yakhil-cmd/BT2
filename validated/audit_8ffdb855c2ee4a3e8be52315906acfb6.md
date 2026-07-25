### Title
Push-Pattern KLAY Delivery in `handleKLAYTransfer` Permanently Locks Bridged KLAY When `_to` Is a Reverting Contract — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` uses a push pattern to deliver KLAY to the recipient `_to`. If `_to` is a contract that reverts on receiving KLAY, the entire transaction reverts, the bridge nonce is never consumed, and the user's KLAY locked in the source-chain bridge is permanently unrecoverable. There is no pull-withdrawal fallback and no admin rescue path.

---

### Finding Description

In `BridgeTransferKLAY.sol`, `handleKLAYTransfer` (called by bridge operators on the destination chain) performs a push transfer as its final step:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [1](#0-0) 

Because `require(ok, ...)` causes a full EVM revert, every state mutation that preceded it — including `_setHandledRequestTxHash`, `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber`, and `_updateHandleNonce` — is also rolled back: [2](#0-1) 

`_updateHandleNonce` advances `lowerHandleNonce` only while consecutive nonces have `handleNoncesToBlockNums[i] > 0`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
``` [3](#0-2) 

Because the stuck nonce's entry is never written (the tx always reverts), `lowerHandleNonce` is permanently frozen at that nonce. The `recoveryBlockNumber` also stops advancing, corrupting the off-chain recovery cursor.

On the source chain, the user's KLAY was already deposited into the source bridge via `_requestKLAYTransfer` (`msg.value` is retained by the contract): [4](#0-3) 

There is no refund path back to the user and no owner-callable rescue/withdrawal function anywhere in the bridge contract hierarchy. The KLAY is permanently locked.

---

### Impact Explanation

| Asset | Effect |
|---|---|
| User's KLAY (source chain) | Permanently locked in source bridge — no refund mechanism |
| Bridge's KLAY (destination chain) | Permanently undeliverable for the stuck nonce |
| `lowerHandleNonce` | Frozen; `recoveryBlockNumber` stops advancing, breaking off-chain recovery |

The destination bridge can still process nonces above the stuck one (the `_lowerHandleNonceCheck` only enforces `lowerHandleNonce <= _requestedNonce`), but the stuck nonce's KLAY is irrecoverable and the recovery cursor is corrupted indefinitely. [5](#0-4) 

---

### Likelihood Explanation

The `_to` address is freely chosen by the user on the source chain when calling `requestKLAYTransfer` or the fallback: [6](#0-5) 

Any user can set `_to` to a contract with no payable fallback, or one that explicitly reverts. This requires no privilege, no operator collusion, and no external service compromise. A single malicious (or accidentally misconfigured) transfer request is sufficient to trigger the condition.

---

### Recommendation

Replace the push delivery with a pull pattern: record the pending KLAY in a per-address mapping inside `handleKLAYTransfer` and expose a `withdraw()` function for recipients to claim their funds. This decouples nonce advancement and state finalization from the external call, exactly as the Moloch Pull Pattern update resolved the analogous issue.

```solidity
mapping(address => uint256) public pendingWithdrawals;

function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    // ... nonce checks and state updates ...
    pendingWithdrawals[_to] += _value;   // pull pattern
}

function withdraw() external nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "nothing to withdraw");
    pendingWithdrawals[msg.sender] = 0;
    (bool ok, ) = msg.sender.call.value(amount)("");
    require(ok, "withdraw failed");
}
```

---

### Proof of Concept

1. Deploy `Reverter` on the destination chain — a contract whose fallback explicitly reverts:
   ```solidity
   contract Reverter { function() external payable { revert(); } }
   ```

2. On the source chain, call:
   ```solidity
   bridge.requestKLAYTransfer{value: 1.5 ether}(address(Reverter), 1 ether, "");
   ```
   This emits `RequestValueTransfer` with nonce `N` and locks 1 ether in the source bridge.

3. Operators observe the event and call on the destination chain:
   ```solidity
   bridge.handleKLAYTransfer(txHash, from, address(Reverter), 1 ether, N, blockNum, "");
   ```

4. The call to `address(Reverter).call.value(1 ether)("")` reverts → `require(ok)` reverts the entire transaction → `handleNoncesToBlockNums[N]` is never written.

5. Every subsequent operator retry for nonce `N` reverts identically. `lowerHandleNonce` is frozen at `N`.

6. The 1 ether on the source chain is permanently locked in the source bridge with no refund path. The destination bridge's KLAY allocated for nonce `N` is permanently undeliverable.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L81-84)
```text
        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
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
