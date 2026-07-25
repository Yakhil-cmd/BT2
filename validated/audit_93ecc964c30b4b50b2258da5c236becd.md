### Title
Stale Operator Votes Persist Indefinitely After Deregistration, Enabling Threshold Bypass for Bridge Value Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from `operators` and `operatorList` but does **not** revoke or zero out that operator's outstanding entries in the `votes[voteType][nonce].voteCounts` mapping. Those vote counts persist indefinitely in contract storage. A subsequent vote by any remaining active operator on the same nonce can push `voteCounts[voteKey]` to or above `operatorThresholds[VoteType.ValueTransfer]`, causing `_voteValueTransfer` to return `true` and the bridge to execute a KAIA/ERC20/ERC721 transfer — with the deregistered operator's contribution still counted.

### Finding Description

In `BridgeOperator.sol`, `_voteCommon` increments `vote.voteCounts[_voteKey]` for the caller and compares it against `operatorThresholds`:

```solidity
vote.voteCounts[_voteKey]++;
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
``` [1](#0-0) 

`deregisterOperator` only removes the address from the `operators` mapping and `operatorList` array; it never touches the `votes` storage:

```solidity
delete operators[_operator];
for (uint i = 0; i < operatorList.length; i++) {
   if (operatorList[i] == _operator) {
       operatorList[i] = operatorList[operatorList.length-1];
       operatorList.length--;
       break;
   }
}
``` [2](#0-1) 

The contract itself documents the resulting scenario in a comment:

> *"Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered."* [3](#0-2) 

The comment says deregistration "takes some time to be fully effective," but there is **no expiry or cleanup mechanism**. The stale `voteCounts` entry persists indefinitely. `_updateHandleNonce` in `BridgeTransfer.sol` deletes `closedValueTransferVotes[i]` for completed nonces but never touches the `votes` mapping:

```solidity
delete handleNoncesToBlockNums[i];
delete closedValueTransferVotes[i];
// votes[voteType][nonce] is never deleted
``` [4](#0-3) 

### Impact Explanation

The bridge contracts (`BridgeTransferKLAY`, `BridgeTransferERC20`, `BridgeTransferERC721`) call `_voteValueTransfer` before executing `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer`. If the threshold is met using a deregistered operator's stale vote, the bridge will transfer KAIA or bridged tokens to the `_to` address. This is an unauthorized asset transfer: the owner deregistered the operator specifically to revoke their authority, but the transfer executes as if that authority were still valid. [5](#0-4) 

### Likelihood Explanation

The scenario requires: (1) operator A votes on request nonce N, (2) the owner deregisters A (e.g., in response to a key compromise), (3) operator B votes on the same nonce N. Step 3 is the normal operational path — bridge operators are expected to vote on every incoming request. The window between steps 1 and 2 is realistic in any incident-response scenario. With threshold = 2 and 3 operators, a single remaining active operator plus the stale deregistered vote suffices to execute the transfer.

### Recommendation

In `deregisterOperator`, iterate over all pending nonces and decrement or zero out the deregistered operator's vote contribution, or add a per-operator "deregistered-at-nonce" watermark that `_voteCommon` checks before counting a vote. Alternatively, store a per-operator deregistration flag and skip their `voteCounts` contribution in `_voteCommon` if the flag is set.

### Proof of Concept

```
Setup: threshold = 2, operators = [Owner, A, B]

1. Request nonce N arrives on the counterpart chain.
2. Operator A calls handleKLAYTransfer(..., N, ...).
   → _voteValueTransfer(N): voteCounts[keccak256(calldata)] = 1. Returns false.
3. Owner calls deregisterOperator(A).
   → operators[A] = false. votes[0][N].voteCounts unchanged (still 1).
4. Operator B calls handleKLAYTransfer(..., N, ...) with identical arguments.
   → _voteCommon: voteCounts[same voteKey]++ → 2 >= threshold(2). Returns true.
   → closedValueTransferVotes[N] = true.
   → Bridge transfers KAIA to _to.

Result: transfer executed with A's vote counted after A was deregistered.
``` [6](#0-5)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L94-99)
```text
        vote.voteCounts[_voteKey]++;

        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L102-116)
```text
    // _voteValueTransfer votes value transfer transaction with the operator.
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L146-158)
```text
    // deregisterOperator deregisters the operator.
    //
    // Note that outstanding votes by the deregistered operator are not revoked.
    // This enables a subtle counterintuitive scenario.
    //
    // Suppose there are two operators A, B and C with threshold 2.
    // 1. Operator A votes on nonce N
    // 2. Owner deregisters A
    // 3. Operator B votes on nonce N, thereby executing the request N.
    // In this case the request was executed with A's vote after A is deregistered.
    //
    // The Owner shall recognize this issue and expect that operator deregistration
    // takes some time to be fully effective.
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L159-174)
```text
    function deregisterOperator(address _operator)
    external
    onlyOwner
    {
        require(operators[_operator]);
        delete operators[_operator];

        for (uint i = 0; i < operatorList.length; i++) {
           if (operatorList[i] == _operator) {
               operatorList[i] = operatorList[operatorList.length-1];
               operatorList.length--;
               break;
           }
        }
        emit OperatorDeregistered(_operator);
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
