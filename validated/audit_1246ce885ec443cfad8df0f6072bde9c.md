### Title
Deregistered Bridge Operator's Outstanding Votes Remain Counted, Enabling Unauthorized Value Transfer Execution — (File: `contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator.deregisterOperator` removes an operator from the `operators` mapping and `operatorList` array but does **not** clear that operator's accumulated vote counts from the `votes` storage. Because `_voteCommon` checks only `vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]` — without verifying that each counted voter is still a registered operator — a deregistered operator's prior vote can still push a nonce over the threshold. A subsequent vote by any remaining active operator then executes `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer`, releasing bridged assets after the operator's authority was supposed to have been revoked.

---

### Finding Description

`deregisterOperator` performs two actions:

1. `delete operators[_operator]` — removes the operator from the active-operator gate used by `onlyOperators`.
2. Removes the address from `operatorList` — used only by `setOperatorThreshold`'s length check. [1](#0-0) 

Neither action touches the `votes` mapping:

```solidity
mapping(uint8 => mapping (uint64 => VotesData)) private votes;
``` [2](#0-1) 

`_voteCommon` tallies votes purely by count:

```solidity
vote.voteCounts[_voteKey]++;
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
``` [3](#0-2) 

There is no check that the addresses whose votes are already stored in `vote.voted` / `vote.voteCounts` are still present in `operators`. Once `_voteValueTransfer` returns `true`, `closedValueTransferVotes[_requestNonce]` is set and the handle functions (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`) proceed to transfer or mint assets. [4](#0-3) 

The code itself documents the inconsistency:

> *"Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered. The Owner shall recognize this issue and expect that operator deregistration takes some time to be fully effective."* [5](#0-4) 

Despite the inline comment, the invariant **"only votes from currently-registered operators count toward the threshold"** is broken. The owner's deregistration action does not atomically revoke the operator's contribution to any in-flight vote, leaving a window where the deregistered operator's vote still drives asset release.

---

### Impact Explanation

When `_voteValueTransfer` returns `true` for a nonce, the handle functions unconditionally transfer KLAY, mint/transfer ERC-20, or mint/transfer ERC-721 to the destination address: [6](#0-5) [7](#0-6) 

A deregistered operator's vote contributing to threshold satisfaction causes bridged assets (KLAY, ERC-20, ERC-721) to be transferred to an attacker-controlled address without the full set of currently-authorized operators having approved the request. This is an unauthorized transfer of bridged assets.

---

### Likelihood Explanation

The scenario requires:
1. A compromised or malicious operator (A) to cast a vote on a value-transfer nonce before being deregistered.
2. The bridge owner to deregister A, believing the pending transfer is now blocked.
3. Any remaining active operator (B) to cast a vote on the same nonce (possibly colluding with A, or simply processing a legitimate-looking request).

With threshold = 2 and two operators, a single colluding pair suffices. The owner's deregistration of A does not prevent step 3 from completing the transfer. The window persists until the nonce is either closed by a legitimate execution or the `lowerHandleNonce` advances past it.

---

### Recommendation

`deregisterOperator` should iterate over all open (non-closed) nonces for `VoteType.ValueTransfer` and `VoteType.Configuration` and subtract the deregistered operator's vote count from `vote.voteCounts` (and remove the address from `vote.voters`). Alternatively, `_voteCommon` should re-validate `operators[voter]` for every address in `vote.voters` before comparing the count to the threshold. A simpler mitigation is to require the owner to call `setOperatorThreshold` to a value achievable by the remaining operators before or atomically with `deregisterOperator`, and to document that any nonce already voted on by the departing operator must be explicitly cancelled.

---

### Proof of Concept

```
State: operators = {A, B}, threshold(ValueTransfer) = 2

1. Operator A calls handleKLAYTransfer(txHash, from, to, 1 ether, nonce=5, blk=100)
   → _voteCommon: vote.voteCounts[keccak(msg.data)] = 1  (< threshold 2, returns false)
   → transfer NOT executed yet

2. Owner calls deregisterOperator(A)
   → operators[A] = false, operatorList shrinks
   → votes[ValueTransfer][5].voteCounts unchanged (still 1 for A's voteKey)

3. Operator B calls handleKLAYTransfer(txHash, from, to, 1 ether, nonce=5, blk=100)
   → onlyOperators: operators[B] = true ✓
   → _voteCommon: vote.voteCounts[same voteKey]++ → 2 >= threshold 2 → returns true
   → closedValueTransferVotes[5] = true
   → 1 ether transferred to `to`

Result: 1 ether released using A's vote cast after A was deregistered.
        The owner's deregistration of A did not prevent the transfer.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L34-35)
```text
    mapping(uint8 => mapping (uint64 => VotesData)) private votes; // <voteType, <nonce, VotesData>
    mapping(uint64 => bool) public closedValueTransferVotes; // <nonce, bool>
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L63-67)
```text
    modifier onlyOperators()
    {
        require(operators[msg.sender], "msg.sender is not an operator");
        _;
    }
```

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L61-99)
```text
    // handleKLAYTransfer sends the KLAY by the request.
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
