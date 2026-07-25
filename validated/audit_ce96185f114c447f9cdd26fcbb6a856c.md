### Title
Deregistered Bridge Operator's Votes Persist and Count Toward Execution Threshold — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from `operators` and `operatorList` but does not clear that operator's accumulated `voteCounts` entries in `VotesData`. A deregistered operator's vote remains in the tally and can combine with votes from remaining operators to reach the execution threshold, causing unauthorized bridge value transfers (KAIA, ERC20, ERC721) to execute.

### Finding Description

`_voteCommon` stores per-nonce vote tallies in `votes[voteType][nonce].voteCounts[voteKey]`. When `deregisterOperator` is called, it deletes the operator from `operators` and shrinks `operatorList`, but leaves `voteCounts` untouched. [1](#0-0) 

The threshold check in `_voteCommon` compares the raw accumulated count against the fixed `operatorThresholds` value: [2](#0-1) 

`operatorThresholds` is not automatically adjusted when operators are removed. The stale vote count from the deregistered operator is never decremented. A deregistered operator also cannot self-revoke: the re-vote path inside `_voteCommon` (lines 81–86) is gated by `onlyOperators` on every public entry point (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`). [3](#0-2) [4](#0-3) 

The code comment at lines 147–158 acknowledges the scenario but frames it as an operator-management concern, not as a security boundary: [5](#0-4) 

### Impact Explanation

When the threshold is reached using a stale vote, `_voteValueTransfer` sets `closedValueTransferVotes[nonce] = true` and the calling `handle*Transfer` function immediately executes the asset movement — minting or transferring ERC20 tokens, transferring KAIA, or transferring ERC721 tokens to an arbitrary `_to` address. [6](#0-5) [7](#0-6) 

The corrupted value is `votes[ValueTransfer][N].voteCounts[voteKey]`: it is inflated by one stale count that should have been zeroed on deregistration. The resulting bridge transfer is irreversible once `closedValueTransferVotes[N]` is set.

### Likelihood Explanation

The attack requires two colluding operators. Operator A votes for a fraudulent transfer, gets caught and deregistered by the Owner, but A's vote count persists. Operator B (still active, colluding with A) then votes for the same nonce, reaching the threshold. The Owner's remediation action (deregistering A) is rendered ineffective. With a threshold of 2 and 3 operators this is a single-step exploit after deregistration.

### Recommendation

In `deregisterOperator`, iterate over all open `VotesData` entries for the deregistered operator and decrement `voteCounts` for any nonce where `vote.voted[_operator] != bytes32(0)`, then clear `vote.voted[_operator]`. Alternatively, record a "deregistration epoch" and reject stale votes cast before that epoch during threshold evaluation.

### Proof of Concept

```
Setup:
  operators = [A, B, C], operatorThresholds[ValueTransfer] = 2

Step 1: A calls handleERC20Transfer(..., nonce=7, ...) with fraudulent _to and _value.
        votes[0][7].voteCounts[voteKey] = 1
        votes[0][7].voted[A] = voteKey

Step 2: Owner calls deregisterOperator(A).
        operators[A] deleted, operatorList shrinks to [B, C].
        votes[0][7].voteCounts[voteKey] still = 1  ← stale

Step 3: B calls handleERC20Transfer(..., nonce=7, same args).
        _voteCommon: voteCounts[voteKey]++ → 2
        2 >= operatorThresholds[0] (= 2) → returns true
        closedValueTransferVotes[7] = true
        ERC20.safeTransfer(fraudulent _to, _value) executes.

Result: Bridge transfers tokens to attacker-controlled address using A's
        revoked vote, despite A having been deregistered as a remediation.
``` [8](#0-7) [9](#0-8)

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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L146-174)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L42-72)
```text
        public
        onlyOperators
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
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L72-99)
```text
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
```
