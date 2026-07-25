### Title
Reverting Fallback in KLAY Bridge Recipient Permanently Locks Bridged KLAY and Freezes `lowerHandleNonce` — (`File: contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in the service-chain bridge uses a push-transfer pattern: it calls `_to.call.value(_value)("")` and then `require(ok, ...)`. If `_to` is a smart contract whose fallback reverts, the entire transaction reverts — including the nonce accounting. Because there is no admin escape hatch to skip or redirect a stuck nonce, the KLAY for that request is permanently locked inside the bridge contract and `lowerHandleNonce` is frozen forever, breaking the sequential recovery invariant for all subsequent nonces.

---

### Finding Description

In `contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `handleKLAYTransfer` performs all state mutations (nonce update, vote closure, event emission) and then attempts the native-token push:

```solidity
// BridgeTransferKLAY.sol L98-99
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [1](#0-0) 

Because `require(ok, ...)` causes a full EVM revert on failure, every state write that preceded it is also rolled back:

- `handleNoncesToBlockNums[_requestedNonce]` is never persisted.
- `_updateHandleNonce` never runs to completion.
- `closedValueTransferVotes[_requestedNonce]` is never cleared. [2](#0-1) 

`_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive nonces starting from `lowerHandleNonce`:

```solidity
// BridgeTransfer.sol L150-155
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
``` [3](#0-2) 

If nonce N is never successfully handled, `handleNoncesToBlockNums[N]` stays zero, the loop halts at N, and `lowerHandleNonce` is permanently frozen at N. There is no owner/operator function in the contract to skip a nonce, redirect funds, or force-advance `lowerHandleNonce`.

---

### Impact Explanation

1. **Permanent KLAY lock**: The KLAY deposited on the parent chain for the stuck request is held in the child-chain bridge contract indefinitely. No function exists to withdraw or redirect it.
2. **`lowerHandleNonce` frozen**: `recoveryBlockNumber` (used by the off-chain recovery scanner) never advances past the stuck nonce. The bridge's recovery mechanism will perpetually re-scan from the same old block, and the accounting invariant `lowerHandleNonce ≤ all handled nonces` is broken.
3. **Scope**: Affects bridged KAIA (native token) on the service-chain bridge — a system-managed fund with direct asset impact.

---

### Likelihood Explanation

The trigger is a user calling `requestKLAYTransfer` on the parent-chain bridge with `_to` set to a contract address whose fallback reverts. This is a normal, permissionless user action. The user may do this accidentally (e.g., a multisig or DAO contract that rejects plain ETH/KAIA transfers) or intentionally as a griefing attack. Bridge operators have no way to override the `_to` address; they must relay exactly what the event specifies. [4](#0-3) 

---

### Recommendation

Replace the push pattern with a pull pattern, mirroring the fix described in the seed report:

1. **Store instead of send**: Replace the `call.value` with a credit to a `mapping(address => uint256) pendingWithdrawals` inside `handleKLAYTransfer`. The nonce is consumed and the KLAY is credited atomically.
2. **Add `withdrawKLAY()`**: Let the recipient call a separate `withdrawKLAY()` function to pull their credited balance. A reverting fallback on their side only harms themselves.
3. **Alternative — ignore failure**: If the pull pattern is too invasive, at minimum remove the `require(ok, ...)` and emit a `TransferFailed` event so operators can detect and manually remediate stuck transfers without freezing the nonce.

---

### Proof of Concept

1. Deploy a contract `Rejecter` on the child chain with a reverting fallback:
   ```solidity
   contract Rejecter { fallback() external payable { revert(); } }
   ```
2. On the parent chain, call `bridge.requestKLAYTransfer(address(rejecter), 1 ether, "")` with `msg.value = 1 ether`. This emits `RequestValueTransfer` with `_to = address(rejecter)`.
3. Bridge operators observe the event and call `handleKLAYTransfer(..., address(rejecter), 1 ether, N, ...)` on the child-chain bridge (which holds sufficient KLAY).
4. The call to `rejecter.call.value(1 ether)("")` returns `ok = false`. `require(ok, ...)` reverts the entire transaction.
5. Observe: `bridge.lowerHandleNonce()` is still `N` (or whatever it was before). `bridge.handleNoncesToBlockNums(N)` is `0`. The 1 KLAY remains in the bridge contract.
6. Every subsequent operator retry for nonce N also reverts. The KLAY is permanently locked and `lowerHandleNonce` is frozen. [5](#0-4) [3](#0-2)

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
