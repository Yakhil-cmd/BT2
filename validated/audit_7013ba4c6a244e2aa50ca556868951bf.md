### Title
KLAY Bridge Permanently Stuck When `_to` Cannot Receive KLAY — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`handleKLAYTransfer` uses a push-over-pull pattern to deliver KLAY to the recipient. If `_to` is a contract that cannot receive KLAY, the `require(ok, ...)` at line 99 reverts the entire transaction, undoing all state changes including the nonce advancement. Because there is no mechanism to skip a stuck nonce, the bridge's `lowerHandleNonce` is permanently frozen, locking the KLAY in the bridge and blocking the recovery system.

### Finding Description

In `BridgeTransferKLAY.sol`, `handleKLAYTransfer` executes the following sequence:

1. Validates nonce via `_lowerHandleNonceCheck` [1](#0-0) 
2. Reaches operator vote threshold via `_voteValueTransfer` [2](#0-1) 
3. Records `handleNoncesToBlockNums[_requestedNonce]` and calls `_updateHandleNonce` [3](#0-2) 
4. **Then** pushes KLAY to `_to` and requires success: [4](#0-3) 

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
```

If `_to` is a contract with no payable fallback, `ok` is `false` and the entire transaction reverts. All state changes — including `handleNoncesToBlockNums[N]`, `closedValueTransferVotes[N]`, and the `lowerHandleNonce` advancement — are rolled back.

The `_updateHandleNonce` loop advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive nonces starting from `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
``` [5](#0-4) 

Since `handleNoncesToBlockNums[N]` is never durably set (always reverted), `lowerHandleNonce` is permanently frozen at `N`. There is no `skipNonce`, `cancelTransfer`, or admin escape hatch in the contract.

The `_to` address is fully user-controlled: `requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData)` accepts any address as the counterpart-chain recipient. [6](#0-5) 

### Impact Explanation

- **KLAY locked**: The KLAY held in the destination bridge for nonce N can never be delivered; it is permanently locked.
- **Bridge nonce frozen**: `lowerHandleNonce` never advances past N. The `recoveryBlockNumber` also never advances, causing the off-chain recovery system (`vt_recovery`) to perpetually re-scan from the same block. [7](#0-6) 
- **Operator DoS**: Every attempt by operators to handle nonce N reverts, wasting gas indefinitely with no path to resolution.

This matches the allowed impact gate: unauthorized lock of bridged KAIA assets and persistent corruption of bridge nonce state that breaks settlement.

### Likelihood Explanation

Any user who can call `requestKLAYTransfer` on the source bridge can trigger this. The attacker deploys a contract with no payable fallback on the destination chain, then calls `requestKLAYTransfer` specifying that contract as `_to`. No special privilege is required. The cost is only the KLAY transferred plus gas.

### Recommendation

Apply the pull-over-push pattern: instead of pushing KLAY to `_to` inside `handleKLAYTransfer`, record the claimable balance in a mapping and let `_to` withdraw it separately. Alternatively, if push is retained, catch the failure and emit a `TransferFailed` event while still advancing the nonce, so the bridge is never permanently stuck:

```solidity
(bool ok, ) = _to.call.value(_value)("");
if (!ok) {
    emit KLAYTransferFailed(_requestedNonce, _to, _value);
    // KLAY remains in bridge; _to can be refunded via separate claim
} 
// nonce already advanced above — do not revert
```

### Proof of Concept

1. Attacker deploys `NoReceive` contract on the destination chain (no payable fallback).
2. Attacker calls `requestKLAYTransfer(address(noReceive), 1 ether, "")` on the source bridge, sending `1 ether + fee`. [6](#0-5) 
3. Bridge operators observe the `RequestValueTransfer` event with nonce N and call `handleKLAYTransfer(..., address(noReceive), 1 ether, N, ...)` on the destination bridge.
4. Inside `handleKLAYTransfer`, `_updateHandleNonce(N)` runs (setting `handleNoncesToBlockNums[N]`), then `_to.call.value(1 ether)("")` returns `false` because `NoReceive` has no payable fallback. [4](#0-3) 
5. `require(ok, ...)` reverts the transaction. All state changes including `handleNoncesToBlockNums[N]` are rolled back.
6. `lowerHandleNonce` remains at N. Every subsequent operator attempt to handle nonce N reverts identically.
7. `recoveryBlockNumber` never advances; the off-chain recovery system loops forever. [8](#0-7) 
8. The 1 KLAY is permanently locked in the destination bridge contract.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L75-75)
```text
        _lowerHandleNonceCheck(_requestedNonce);
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L77-79)
```text
        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L83-84)
```text
        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-134)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L31-34)
```text
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
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
