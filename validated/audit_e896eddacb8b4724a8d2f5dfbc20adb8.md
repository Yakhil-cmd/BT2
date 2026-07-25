### Title
Deregistered Bridge Operator's Votes Persist and Can Still Satisfy Threshold — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from the `operators` mapping and `operatorList`, but does **not** clear that operator's already-cast votes from the `votes` storage mapping. Those residual votes remain counted in `voteCounts` and can combine with votes from still-active operators to reach the threshold, causing `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` to execute a bridge asset transfer that the owner intended to block by deregistering the operator.

### Finding Description

`BridgeOperator` stores per-nonce vote state in a private nested mapping:

```
mapping(uint8 => mapping(uint64 => VotesData)) private votes;
```

where `VotesData` holds `voted[address] => voteKey` and `voteCounts[voteKey] => uint8`.

When an operator votes, `_voteCommon` increments `voteCounts[voteKey]` and checks it against `operatorThresholds`:

```solidity
vote.voteCounts[_voteKey]++;
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
```

When the owner calls `deregisterOperator`, only the live-operator state is cleared:

```solidity
delete operators[_operator];
// removes from operatorList array
```

The `votes[voteType][nonce].voted[_operator]` entry and the corresponding `voteCounts` increment are **never touched**. The deregistered operator's vote weight persists indefinitely for every open nonce.

The contract itself documents this in a comment:

> "Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered."

### Impact Explanation

A deregistered operator's residual vote can combine with a vote from a currently-active operator to satisfy the threshold and trigger `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer`. This causes an unauthorized transfer of KAIA or bridged ERC-20/ERC-721 tokens on the destination chain — an asset transfer that the owner explicitly tried to prevent by revoking the operator's authority.

Concrete corrupted value: the `closedValueTransferVotes[nonce]` flag is set to `true` and the token transfer executes, even though the effective quorum at execution time includes a vote from an address that is no longer a registered operator.

### Likelihood Explanation

The scenario requires:
1. Operator A votes on nonce N (legitimate action while registered).
2. Owner deregisters A (e.g., key rotation, compromise response).
3. Any remaining active operator B votes on the same nonce N with identical parameters.
4. `voteCounts[voteKey]` reaches threshold; transfer executes.

Step 3 is the normal operational path — operators are expected to relay every cross-chain request. The owner's intent to block the transfer by deregistering A is silently defeated. The window is bounded only by how quickly the remaining operators process pending nonces after a deregistration event.

### Recommendation

In `deregisterOperator`, iterate over all open nonces for `VoteType.ValueTransfer` and decrement (or zero) the deregistered operator's vote contribution, or invalidate the operator's `voted` entry so that `_voteCommon` treats it as a fresh voter on the next call. A simpler alternative is to record a per-operator "deregistration epoch" and reject votes cast before that epoch when tallying `voteCounts`.

### Proof of Concept

Setup: operators = {A, B}, threshold = 2.

1. Operator A calls `handleKLAYTransfer(txHash, from, to, value, nonce=5, blockNum, data)`.
   - `_voteValueTransfer(5)` → `_voteCommon` stores `voted[A] = voteKey`, `voteCounts[voteKey] = 1`. Threshold not reached; returns `false`. No transfer.
2. Owner calls `deregisterOperator(A)`.
   - `operators[A]` deleted. `operatorList` shrunk. `votes[0][5]` untouched: `voteCounts[voteKey]` still `= 1`.
3. Operator B calls `handleKLAYTransfer(txHash, from, to, value, nonce=5, blockNum, data)` (same parameters).
   - `_voteValueTransfer(5)` → `_voteCommon` stores `voted[B] = voteKey`, `voteCounts[voteKey]++` → `= 2`. `2 >= threshold(2)` → returns `true`.
   - `closedValueTransferVotes[5] = true`. `_to.call.value(value)("")` executes. KAIA transferred.

The transfer executes with A's deregistered vote counting, contrary to the owner's intent. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-99)
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
