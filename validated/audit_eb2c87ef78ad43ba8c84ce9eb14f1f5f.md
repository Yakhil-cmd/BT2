### Title
Deregistered Operator's Stale Vote Persists and Can Execute Unauthorized Bridge Value Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from the active set but does not revoke their outstanding votes stored in the `votes` mapping. A subsequent vote by any remaining active operator can reach the threshold using the deregistered operator's stale `voteCount`, executing a KLAY/ERC20/ERC721 value transfer that the bridge owner intended to prevent.

---

### Finding Description

The `_voteCommon()` function accumulates per-nonce vote counts in `votes[voteType][nonce].voteCounts[voteKey]` and fires when the count reaches `operatorThresholds[voteType]`. [1](#0-0) 

`deregisterOperator()` only deletes the operator from `operators` and splices `operatorList`. It does **not** touch `votes[voteType][nonce].voted[operator]` or decrement `votes[voteType][nonce].voteCounts[voteKey]` for any nonce the operator has already voted on. [2](#0-1) 

The code itself acknowledges this at lines 146–158:

> *"Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered. The Owner shall recognize this issue and expect that operator deregistration takes some time to be fully effective."* [3](#0-2) 

The acknowledgement documents the gap but provides no fix. The `_voteValueTransfer()` guard only checks `closedValueTransferVotes[_requestNonce]` (replay prevention) and the `onlyOperators` modifier on the *caller* — neither check whether any previously-recorded voter is still a registered operator. [4](#0-3) 

The downstream `handleKLAYTransfer` (and its ERC20/ERC721 equivalents) unconditionally transfers assets once `_voteValueTransfer` returns `true`. [5](#0-4) 

---

### Impact Explanation

A KLAY/ERC20/ERC721 transfer is executed on the destination bridge using a vote cast by an operator who has since been deregistered. The bridge owner's defensive action — deregistering a compromised or malicious operator — is **immediately ineffective** for any nonce that operator has already voted on. The corrupted value is the bridged asset amount transferred to the attacker-controlled `_to` address.

This matches the allowed impact: *"Unauthorized transfer … affecting KAIA, bridged assets, or system-managed funds."*

---

### Likelihood Explanation

The scenario is realistic and requires no privileged collusion beyond what the protocol already permits:

1. Operator A (compromised or malicious) votes on a fraudulent transfer nonce N.
2. The bridge owner detects the malicious vote and calls `deregisterOperator(A)`.
3. Any remaining active operator B (who may be colluding with A, or who is simply processing a backlog of legitimate requests) calls `handleKLAYTransfer` with the same parameters for nonce N.
4. The threshold is met using A's stale vote → transfer executes.

The window is bounded only by how quickly the owner can deregister A relative to B's next transaction, which in a live service-chain environment can be seconds.

---

### Recommendation

In `deregisterOperator()`, iterate over all pending `VotesData` entries for the removed operator and decrement the corresponding `voteCounts`:

```solidity
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);
    delete operators[_operator];

    // Revoke outstanding votes for both vote types
    for (uint8 vt = 0; vt < uint8(VoteType.Max); vt++) {
        // Iterate over known open nonces and clear the operator's vote
        // (requires tracking open nonces, or a per-operator vote index)
    }

    // ... existing operatorList splice ...
    emit OperatorDeregistered(_operator);
}
```

A simpler alternative: add a check inside `_voteCommon()` that skips (or subtracts) vote counts from addresses no longer in `operators` before comparing against the threshold.

---

### Proof of Concept

```
Setup:
  - Bridge deployed with operators [A, B], threshold = 2
  - Bridge holds 100 KLAY

Step 1: Operator A calls handleKLAYTransfer(txHash, from, attacker, 100 KLAY, nonce=5, blockNum, data)
        → _voteCommon: voteCounts[voteKey] = 1 < 2, returns false
        → transfer NOT executed

Step 2: Owner detects A is malicious, calls deregisterOperator(A)
        → operators[A] = false, operatorList shrinks
        → votes[ValueTransfer][5].voteCounts[voteKey] still = 1  ← stale

Step 3: Operator B (colluding or unaware) calls handleKLAYTransfer(txHash, from, attacker, 100 KLAY, nonce=5, blockNum, data)
        → onlyOperators: B is still registered ✓
        → _voteValueTransfer: closedValueTransferVotes[5] = false ✓
        → _voteCommon: voteCounts[voteKey]++ → 2 >= threshold(2) → returns true
        → closedValueTransferVotes[5] = true
        → 100 KLAY transferred to attacker

Result: 100 KLAY drained despite owner's deregistration of A.
```

The root cause is identical to the DittoETH M-06 analog: a record in a "cancelled/removed" state (`operators[A] = false`) is not checked when its stale reference (`voteCounts`) is consumed to authorize a protected asset transfer.

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L74-100)
```text
    function _voteCommon(VoteType _voteType, uint64 _nonce, bytes32 _voteKey)
        private
        returns(bool)
    {
        VotesData storage vote = votes[uint8(_voteType)][_nonce];

        // If the same voter voted again, revoke previous vote.
        bytes32 oldVoteKeyOfVoter = vote.voted[msg.sender];
        if (oldVoteKeyOfVoter == bytes32(0)) {
            vote.voters.push(msg.sender);
        } else {
            vote.voteCounts[oldVoteKeyOfVoter]--;
        }

        // Either the current voter has voted before or not, update the vote data.
        vote.voted[msg.sender] = _voteKey;

        if (vote.voteCounts[_voteKey] == 0) {
            vote.voteKeys.push(_voteKey);
        }
        vote.voteCounts[_voteKey]++;

        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
    }
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
