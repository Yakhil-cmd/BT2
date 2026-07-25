### Title
Deregistered Bridge Operator's Votes Persist and Can Authorize Unauthorized Value Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator.sol`'s `deregisterOperator` removes an operator from the `operators` mapping and `operatorList` but does **not** revoke that operator's already-cast votes stored in the `votes` mapping. A subsequently-registered (or still-registered) second operator can then cast the final vote on the same nonce, causing `_voteCommon` to reach the threshold and execute the value transfer — with one of the authorizing votes belonging to an operator who is no longer registered. This breaks the invariant that **only currently-registered operators can authorize value transfers**.

---

### Finding Description

`_voteCommon` accumulates votes in a per-nonce, per-voteType storage struct:

```
votes[uint8(_voteType)][_nonce].voteCounts[voteKey]++
```

When the count reaches `operatorThresholds[uint8(_voteType)]`, the function returns `true` and the transfer executes. [1](#0-0) 

`deregisterOperator` only clears `operators[_operator]` and removes the address from `operatorList`. It does **not** touch the `votes` mapping:

```solidity
delete operators[_operator];
// operatorList swap-and-pop ...
// votes mapping: untouched
```

The code itself documents this gap:

> *"Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered."* [2](#0-1) 

`handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` all gate on `onlyOperators` for the **caller** at the time of the second vote, but they never verify that every prior voter in the accumulated `voteCounts` is still a registered operator. [3](#0-2) [4](#0-3) 

---

### Impact Explanation

When the threshold is met using a deregistered operator's stale vote, the bridge contract:

- Calls `_to.call.value(_value)("")` (KLAY transfer) or `IERC20.safeTransfer` / `ERC20Mintable.mint` (ERC20), or mints/transfers an ERC721 token.
- Sets `closedValueTransferVotes[_requestNonce] = true`, permanently marking the nonce as handled.

The result is an **unauthorized transfer of KAIA or bridged ERC20/ERC721 assets** from the bridge contract to an attacker-controlled address, with no way to reverse it once the nonce is closed. This directly matches the allowed impact: *"Unauthorized transfer … affecting KAIA, bridged assets, or system-managed funds."*

---

### Likelihood Explanation

The trigger requires:

1. A registered operator (Operator A) to cast a vote on a value-transfer nonce — a normal, semi-trusted action.
2. The bridge owner to deregister Operator A (e.g., because A's key was suspected compromised) — a privileged but routine administrative action.
3. A second registered operator (Operator B, colluding with A or also compromised) to cast the second vote on the same nonce after A is deregistered.

The owner's deregistration of A creates a **false sense of security**: the owner believes A's influence has been neutralized, but A's vote still counts. The window between A's vote and the owner's deregistration is the attack surface. In a multi-operator bridge with threshold ≥ 2, this window is always present because votes are cast asynchronously across operators.

---

### Recommendation

In `deregisterOperator`, iterate over all open (non-closed) value-transfer nonces and decrement the deregistered operator's vote count if they have voted:

```solidity
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);
    
    // Revoke pending votes for all open value-transfer nonces
    for (uint64 n = lowerHandleNonce; n <= upperHandleNonce; n++) {
        if (closedValueTransferVotes[n]) continue;
        VotesData storage vd = votes[uint8(VoteType.ValueTransfer)][n];
        bytes32 key = vd.voted[_operator];
        if (key != bytes32(0)) {
            vd.voteCounts[key]--;
            delete vd.voted[_operator];
        }
    }
    
    delete operators[_operator];
    // ... operatorList swap-and-pop ...
}
```

Alternatively, when `_voteCommon` checks the threshold, verify that all voters in `vote.voters` are still registered operators before returning `true`.

---

### Proof of Concept

```
Setup:
  - Bridge deployed with operators: Owner (A), Op1 (B), Op2 (C)
  - operatorThresholds[ValueTransfer] = 2
  - Bridge holds 100 KLAY

Attack:
  1. Attacker controls Op1 (B). Op1 calls handleKLAYTransfer(txHash, from,
     attacker_addr, 100 KLAY, nonce=5, blkNum=X).
     → _voteCommon: voteCounts[voteKey] = 1 < 2, returns false. No transfer yet.

  2. Owner discovers Op1 is compromised. Owner calls deregisterOperator(Op1).
     → operators[Op1] = false. operatorList shrinks.
     → votes[0][5].voteCounts[voteKey] still = 1. Op1's vote is NOT revoked.

  3. Owner believes Op1's vote is neutralized. Owner does NOT cancel nonce 5.

  4. Attacker controls Op2 (C, still registered). Op2 calls handleKLAYTransfer(
     txHash, from, attacker_addr, 100 KLAY, nonce=5, blkNum=X).
     → onlyOperators: operators[Op2] = true ✓
     → _voteCommon: voteCounts[voteKey]++ → 2 >= threshold 2 → returns true
     → closedValueTransferVotes[5] = true
     → _to.call.value(100 KLAY)("") executes → 100 KLAY sent to attacker_addr

Result: 100 KLAY transferred to attacker despite Op1 being deregistered.
        The owner's deregistration of Op1 had no effect on the pending vote.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L31-73)
```text
    // handleERC20Transfer sends the token by the request.
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
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
    }
```
