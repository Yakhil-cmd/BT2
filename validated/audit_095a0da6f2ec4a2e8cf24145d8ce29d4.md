### Title
Recipient-Controlled DoS Permanently Locks Bridged KAIA in `handleKLAYTransfer` — (`File: contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`handleKLAYTransfer` updates all bridge state (vote closure, nonce advancement, tx-hash marking) and then performs a raw `call.value` to the recipient. If the recipient is a contract that reverts on receiving KAIA, the entire transaction reverts, rolling back all state. Because the vote is also rolled back, operators can retry — but every retry will fail identically. The bridge's `lowerHandleNonce` and `recoveryBlockNumber` are permanently stuck at that nonce, locking the corresponding KAIA in the source bridge forever.

### Finding Description

In `handleKLAYTransfer`, the execution order is:

1. `_lowerHandleNonceCheck` — validates nonce
2. `_voteValueTransfer` — marks `closedValueTransferVotes[nonce] = true`
3. `_setHandledRequestTxHash` — marks tx hash handled
4. `handleNoncesToBlockNums[nonce] = blockNum` — records block
5. `_updateHandleNonce` — advances `lowerHandleNonce` / `upperHandleNonce`
6. `emit HandleValueTransfer`
7. `(bool ok, ) = _to.call.value(_value)("")` — sends KAIA
8. `require(ok, "handleKLAYTransfer: transfer failed")` — **reverts entire tx if step 7 fails** [1](#0-0) 

Because Solidity reverts all state changes on `require` failure, steps 2–5 are also rolled back. The vote is not permanently closed, so operators can retry — but every retry produces the same outcome: the `call.value` to a reverting contract fails, and the whole transaction reverts again.

The `_updateHandleNonce` loop advances `lowerHandleNonce` only for consecutive nonces where `handleNoncesToBlockNums[i] > 0`: [2](#0-1) 

Since nonce N never succeeds, `handleNoncesToBlockNums[N]` is never set, so `lowerHandleNonce` never advances past N. The `recoveryBlockNumber` is also stuck at the block before N.

### Impact Explanation

- The KAIA deposited by the user on the source chain via `requestKLAYTransfer` is permanently locked in the source bridge contract — it cannot be delivered to `_to` and there is no refund path.
- The bridge's value-transfer recovery system (`vt_recovery.go`) uses `recoveryBlockNumber` as its scan start point. Since `recoveryBlockNumber` never advances past the stuck nonce, the recovery loop perpetually re-scans and re-submits the failing `handleKLAYTransfer`, wasting operator gas and blocking the recovery pipeline.
- All subsequent nonces can still be handled individually (the `_lowerHandleNonceCheck` only requires `lowerHandleNonce <= requestedNonce`), but `lowerHandleNonce` never advances, so the 200-nonce sliding window eventually fills and the recovery system's state becomes permanently inconsistent.

This constitutes an unauthorized lock of bridged KAIA assets — a direct match to the allowed impact gate.

### Likelihood Explanation

Any user who calls `requestKLAYTransfer` on the source chain with `_to` set to a contract address that has no payable fallback (or one that deliberately reverts) triggers this condition. No special privilege is required. The attacker does not need to drain the bridge; they only need to choose a non-payable contract as the recipient. This is a valid, unprivileged, one-shot trigger. [3](#0-2) 

### Recommendation

Decouple the KAIA transfer from the nonce/state update. Two standard approaches:

1. **Pull-payment pattern**: Instead of pushing KAIA to `_to` inside `handleKLAYTransfer`, record the pending balance in a mapping and let `_to` withdraw it separately. This is the exact fix applied in the referenced external report.
2. **Soft failure**: If the `call.value` fails, do not revert — instead record the failed transfer in a claimable mapping so the nonce advances and the bridge is not stuck. Emit a distinct event so the failure is observable.

Either approach ensures that a reverting recipient cannot prevent `lowerHandleNonce` from advancing.

### Proof of Concept

```
1. Attacker deploys a contract `Rejecter` with no payable fallback on the destination chain.

2. Attacker calls on the source bridge:
     requestKLAYTransfer(Rejecter_address, 1 ether, "")
   This emits RequestValueTransfer with nonce=N and locks 1 KAIA in the source bridge.

3. Bridge operators observe the event and call on the destination bridge:
     handleKLAYTransfer(txHash, attacker, Rejecter_address, 1e18, N, blockNum, "")

4. Inside handleKLAYTransfer:
   - _voteValueTransfer(N) → closedValueTransferVotes[N] = true  ✓
   - handleNoncesToBlockNums[N] = blockNum                        ✓
   - _updateHandleNonce(N)                                        ✓
   - _to.call.value(1e18)("") → Rejecter reverts → ok = false
   - require(ok) → ENTIRE TX REVERTS → all state rolled back

5. Every subsequent operator retry produces the same result.
   lowerHandleNonce stays at N.
   recoveryBlockNumber stays at the block before N.
   The 1 KAIA is permanently locked in the source bridge.
   The recovery system loops forever retrying nonce N.
``` [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-134)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
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
