### Title
Stale Votes from Deregistered Bridge Operators Persist and Can Satisfy Threshold for Unauthorized Value Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator._voteCommon` accumulates vote counts in persistent storage keyed by `(voteType, nonce, voteKey)`. When an operator is removed via `deregisterOperator`, their previously cast votes are **never deleted**. A subsequent vote by any still-registered operator for the same transfer parameters can push the accumulated count to or past `operatorThresholds[VoteType.ValueTransfer]`, causing `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` to execute a value transfer that the **current** operator set never fully authorized.

---

### Finding Description

`_voteCommon` writes vote state into `votes[uint8(_voteType)][_nonce]`:

```solidity
vote.voted[msg.sender] = _voteKey;
vote.voteCounts[_voteKey]++;
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
``` [1](#0-0) 

`deregisterOperator` removes the address from `operators` and `operatorList`, but performs **no cleanup** of the `votes` mapping:

```solidity
delete operators[_operator];
// operatorList shrink only — votes[...][...].voted[_operator] and
// votes[...][...].voteCounts[voteKey] are untouched
``` [2](#0-1) 

The code itself documents the consequence:

> "Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered." [3](#0-2) 

`_voteValueTransfer` (called by `handleKLAYTransfer` and `handleERC20Transfer`) only checks `closedValueTransferVotes[_requestNonce]` for replay; it does **not** verify that every counted voter is still a registered operator at execution time: [4](#0-3) 

`handleKLAYTransfer` and `handleERC20Transfer` gate entry with `onlyOperators`, which only prevents a non-operator from *adding* a new vote — it does not invalidate stale votes already in storage: [5](#0-4) [6](#0-5) 

Contrast with `_voteConfiguration`, which uses a sequential global `configurationNonce` that increments on every successful vote, making stale votes for old nonces permanently invalid: [7](#0-6) 

`_voteValueTransfer` has no equivalent global sequential nonce and no expiry timestamp — the two mitigations the external report recommends.

---

### Impact Explanation

A value transfer (KLAY, ERC20, or ERC721) can be executed on the destination bridge using votes from operators who have already been deregistered. The corrupted vote count causes `_voteCommon` to return `true`, which triggers the actual asset transfer (`_to.call.value(_value)("")` for KLAY, `IERC20.safeTransfer` or `ERC20Mintable.mint` for ERC20). This is an unauthorized transfer of bridged assets from the bridge contract.

---

### Likelihood Explanation

**Low.** The attack requires:
1. One or more operators to vote for a specific transfer (nonce N, exact calldata).
2. Those operators to be subsequently deregistered by the owner.
3. A currently registered operator to call `handleKLAYTransfer`/`handleERC20Transfer` with the **identical** parameters (same `_requestedNonce`, `_to`, `_value`, `_requestTxHash`, etc.) so that `keccak256(msg.data)` produces the same `voteKey`.

The most realistic path: a malicious operator votes for a fraudulent transfer, is caught and deregistered, but a colluding current operator later completes the vote. Alternatively, an honest operator unknowingly re-votes for the same nonce/parameters after the malicious operator was removed.

---

### Recommendation

1. **Revoke stale votes on deregistration.** In `deregisterOperator`, iterate over all open `VotesData` entries for the deregistered operator and decrement `voteCounts` for their recorded `voteKey`, then delete `vote.voted[_operator]`.

2. **Validate operator status at threshold check.** In `_voteCommon`, before returning `true`, verify that every address in `vote.voters` is still a registered operator, or maintain a separate "active vote count" that is decremented on deregistration.

3. **Add a global sequential nonce for value-transfer votes** (analogous to `configurationNonce`) so that any operator-set change invalidates all pending votes, forcing operators to re-vote under the new set.

4. **Add an expiry timestamp** to the vote parameters so that votes cast months earlier cannot be used after a configurable deadline.

---

### Proof of Concept

```
Setup:
  operators = [A, B, C], threshold = 3

Step 1: A, B each call handleKLAYTransfer(txHash, from, attacker, 1000 ether, nonce=5, ...)
        → votes[ValueTransfer][5].voteCounts[voteKey] = 2  (threshold not yet met)

Step 2: Owner calls deregisterOperator(A) and deregisterOperator(B)
        → operators = [C], but votes[ValueTransfer][5].voteCounts[voteKey] still = 2

Step 3: Owner lowers threshold to 1 (or adds D,E and threshold stays 3 while C is colluding)
        Simplest: threshold lowered to 1.

Step 4: C calls handleKLAYTransfer(txHash, from, attacker, 1000 ether, nonce=5, ...)
        → _voteCommon increments count to 3, 3 >= 1 (new threshold), returns true
        → closedValueTransferVotes[5] = true
        → 1000 ether transferred to attacker

Result: Transfer executed using two stale votes from deregistered operators A and B,
        combined with one vote from current operator C.
        The current operator set [C] never had quorum under the original threshold of 3.
```

The `votes` mapping retains `voteCounts[voteKey] = 2` from deregistered A and B throughout, and `_voteValueTransfer` never checks whether those voters are still registered. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L73-116)
```text
    // _voteCommon handles common functionality for voting.
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L118-132)
```text
    // _voteConfiguration votes contract configuration transaction with the operator.
    function _voteConfiguration(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(configurationNonce == _requestNonce, "nonce mismatch");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.Configuration, _requestNonce, voteKey)) {
            configurationNonce++;
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
