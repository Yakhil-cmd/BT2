### Title
Deregistered Bridge Operator Votes Persist and Count Toward Execution Threshold, Allowing Value Transfers With Fewer Active Operators Than Required - (File: contracts/service_chain/bridge/BridgeOperator.sol)

### Summary

`BridgeOperator.deregisterOperator` removes an operator from `operatorList` and `operators` mapping but does **not** revoke or decrement that operator's outstanding votes in the `votes` storage mapping. Because `_voteCommon` checks only `vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]` — a raw count that includes deregistered operators' votes — a transfer can be executed with fewer *active* operator votes than the threshold requires.

### Finding Description

`deregisterOperator` removes the operator from the active set: [1](#0-0) 

It does not touch the `votes` mapping. The vote-counting and threshold check in `_voteCommon` is: [2](#0-1) 

`vote.voteCounts[_voteKey]` accumulates votes from all callers, past and present. When an operator is deregistered, their contribution to `voteCounts` remains. The code itself documents the consequence: [3](#0-2) 

The concrete attack path for `handleKLAYTransfer` (which calls `_voteValueTransfer` → `_voteCommon`): [4](#0-3) 

**Step-by-step:**
1. `threshold = 2`, operators = `[A, B]`.
2. Operator A (compromised) calls `handleKLAYTransfer` for malicious nonce N → `voteCounts[voteKey] = 1`.
3. Owner discovers A is compromised and calls `deregisterOperator(A)` → operators = `[B]`, threshold still = 2, but `voteCounts[voteKey]` for nonce N is still 1.
4. Operator B calls `handleKLAYTransfer` for nonce N (B observes the counterpart-chain request and votes, believing A's vote was invalidated by deregistration) → `voteCounts[voteKey] = 2`, `2 >= 2` → **transfer executes**.
5. KAIA is sent to the attacker-controlled `_to` address with only 1 active operator vote (B's), not 2.

The invariant broken: **the threshold is supposed to represent the minimum number of simultaneously-active operators required to authorize a transfer**. After deregistration, the effective active-operator quorum is `threshold - (deregistered votes already cast)`, which can be as low as 1.

### Impact Explanation

`handleKLAYTransfer` sends KAIA directly to `_to`: [5](#0-4) 

An unauthorized value transfer of KAIA (or ERC20/ERC721 tokens via the analogous `handleERC20Transfer`/`handleERC721Transfer`) is executed from the bridge contract to an attacker-controlled address. The corrupted state is `closedValueTransferVotes[N] = true` and the KAIA balance of the bridge contract, both of which are irreversible on-chain.

### Likelihood Explanation

- **Trigger**: a compromised bridge operator (semi-trusted role) casts a vote on a malicious transfer request, then is deregistered.
- **Completion**: one additional active operator votes on the same nonce — plausible because operators independently observe counterpart-chain events and vote on them; B may vote on nonce N believing it is a legitimate request and that A's vote was nullified.
- **No majority collusion required**: only 1 active operator (B) needs to vote after A's deregistered vote is already in storage.
- **Owner action does not prevent it**: the owner's deregistration of A is the intended protective action, but it fails to achieve its purpose.

### Recommendation

In `deregisterOperator`, iterate over all open vote nonces for the deregistered operator and decrement `voteCounts` for their recorded `voted[_operator]` entry, then clear `voted[_operator]`. Alternatively, add a check in `_voteCommon` that verifies `operators[msg.sender]` is still true at vote-count time (already enforced by `onlyOperators` on the outer call, but the *stored* votes from previously-active operators are not re-validated). The cleanest fix is to revoke pending votes on deregistration, analogous to the RocketDAO resolution of requiring the minimum viable member count as the minimum quorum.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
// Demonstrates: deregistered operator vote persists and completes threshold

// Setup: threshold=2, operators=[owner, opA, opB]
// owner deregisters opA after opA votes; opB's single vote then executes the transfer.

bridge.setOperatorThreshold(VoteType.ValueTransfer, 2);
// opA (compromised) votes on malicious nonce 99
bridge.connect(opA).handleKLAYTransfer(txHash, from, attacker, 1 ether, 99, blockNum, "");
// voteCounts[voteKey] == 1, not yet executed

// Owner discovers opA is compromised and deregisters
bridge.connect(owner).deregisterOperator(opA.address);
// operators=[owner, opB], threshold=2, but voteCounts[voteKey] still == 1

// opB votes on nonce 99 (observing the counterpart-chain request, believing A's vote is gone)
bridge.connect(opB).handleKLAYTransfer(txHash, from, attacker, 1 ether, 99, blockNum, "");
// voteCounts[voteKey] == 2 >= threshold(2) → EXECUTES
// 1 ether sent to attacker with only 1 active-operator vote (opB's)
``` [2](#0-1) [1](#0-0)

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
