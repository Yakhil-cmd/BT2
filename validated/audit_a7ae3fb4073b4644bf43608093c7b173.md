### Title
Deregistered Bridge Operator's Votes Remain Valid, Enabling Unauthorized Asset Transfer — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from the active set but does **not** revoke that operator's outstanding votes on pending value-transfer or configuration nonces. A subsequent vote from any remaining active operator can push the accumulated count to the threshold, executing a bridge transfer that the owner intended to block by deregistering the compromised operator.

### Finding Description

`_voteCommon` accumulates votes in `votes[voteType][nonce].voteCounts[voteKey]` and fires when the count reaches `operatorThresholds[voteType]`. [1](#0-0) 

`deregisterOperator` deletes the operator from `operators` and removes them from `operatorList`, but leaves every entry in `votes[*][*].voted[operator]` and `votes[*][*].voteCounts[*]` untouched. [2](#0-1) 

The contract itself documents the exact attack scenario in the `deregisterOperator` NatSpec comment:

> *"Suppose there are two operators A, B and C with threshold 2. 1. Operator A votes on nonce N. 2. Owner deregisters A. 3. Operator B votes on nonce N, thereby executing the request N. In this case the request was executed with A's vote after A is deregistered."* [3](#0-2) 

`handleKLAYTransfer` and `handleERC20Transfer` both call `_voteValueTransfer`, which calls `_voteCommon` and, on threshold, sets `closedValueTransferVotes[nonce] = true` and immediately executes the asset transfer. [4](#0-3) [5](#0-4) 

### Impact Explanation

When the bridge owner deregisters a compromised or malicious operator to stop a fraudulent transfer, the deregistered operator's already-cast vote persists in contract storage. Any remaining active operator who subsequently calls `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` for the same nonce will push the count to threshold, causing the bridge to transfer KLAY or bridged ERC-20/ERC-721 tokens to the attacker-controlled recipient. The owner's remediation action (deregistration) is silently ineffective for nonces that already have a partial vote from the removed operator.

### Likelihood Explanation

The scenario requires:
1. A semi-trusted operator to vote on a nonce (normal operation).
2. The owner to deregister that operator (the expected remediation).
3. Any remaining active operator to vote on the same nonce (normal operation).

Steps 1 and 3 are routine bridge operations. Step 2 is the owner's intended security response. The window between step 1 and step 3 can be arbitrarily long because `closedValueTransferVotes` has no expiry. The code explicitly acknowledges this scenario, confirming it is reachable in practice.

### Recommendation

In `deregisterOperator`, iterate over all open nonces and decrement `voteCounts` for any `voteKey` the deregistered operator has voted on, then clear `voted[_operator]`. Alternatively, store a per-vote "operator-active-at-vote-time" snapshot and re-validate operator membership at threshold-check time. At minimum, the threshold check in `_voteCommon` should verify that each counted voter is still in `operators` before comparing against `operatorThresholds`.

### Proof of Concept

```
Setup: operators = {A, B, C}, threshold = 2

1. Operator A calls handleKLAYTransfer(txHash, from, victim, 100 KLAY, nonce=5, ...)
   → votes[ValueTransfer][5].voted[A] = voteKey
   → votes[ValueTransfer][5].voteCounts[voteKey] = 1  (threshold not reached)

2. Owner calls deregisterOperator(A)
   → operators[A] = false, operatorList shrinks
   → votes[ValueTransfer][5].voteCounts[voteKey] still = 1  ← BUG

3. Operator B calls handleKLAYTransfer(txHash, from, victim, 100 KLAY, nonce=5, ...)
   → votes[ValueTransfer][5].voteCounts[voteKey] = 2  ≥ threshold
   → closedValueTransferVotes[5] = true
   → 100 KLAY transferred to victim  ← unauthorized transfer executed with A's revoked vote
```

The `_voteCommon` function never checks whether `msg.sender`'s prior voters are still registered operators; it only checks `operators[msg.sender]` for the *current* caller via the `onlyOperators` modifier on the outer `handleKLAYTransfer` function. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L63-67)
```text
    modifier onlyOperators()
    {
        require(operators[msg.sender], "msg.sender is not an operator");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L74-99)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
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
