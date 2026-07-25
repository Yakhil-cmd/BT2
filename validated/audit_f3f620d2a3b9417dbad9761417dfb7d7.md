### Title
Deregistered Bridge Operator's Votes Persist and Can Execute Unauthorized KAIA/Token Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from the active set but does **not** revoke their outstanding votes stored in the `votes` mapping. A deregistered operator's vote count persists and can still satisfy the threshold check in `_voteCommon`, allowing a bridge value transfer to execute with authorization from an operator who is no longer trusted. This is the direct Kaia analog of the external bug: an entity simultaneously occupying two mutually exclusive states (active / deregistered) bypasses a protected-state gate.

---

### Finding Description

`BridgeOperator.sol` implements a multi-operator voting system. Every `handleKLAYTransfer` / `handleERC20Transfer` call is gated by `onlyOperators` and internally calls `_voteValueTransfer` → `_voteCommon`. `_voteCommon` increments `vote.voteCounts[voteKey]` and fires the transfer when the count reaches `operatorThresholds`:

```solidity
// BridgeOperator.sol lines 94-98
vote.voteCounts[_voteKey]++;

if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
``` [1](#0-0) 

`deregisterOperator()` removes the operator from `operators[addr]` and `operatorList`, but leaves every entry in `votes[voteType][nonce].voted[addr]` and `votes[voteType][nonce].voteCounts[voteKey]` untouched:

```solidity
// BridgeOperator.sol lines 159-174
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);
    delete operators[_operator];          // ← only the active-flag is cleared
    // votes mapping is never touched
    ...
}
``` [2](#0-1) 

The code itself acknowledges the consequence in a comment, but frames it as an operational caveat rather than a security invariant violation:

> *"Note that outstanding votes by the deregistered operator are not revoked. This enables a subtle counterintuitive scenario … The Owner shall recognize this issue and expect that operator deregistration takes some time to be fully effective."* [3](#0-2) 

The invariant that must hold is: **only currently-registered operators' votes may count toward the threshold**. Because `_voteCommon` never re-validates whether each historical voter is still in `operators`, this invariant is broken. The deregistered operator is simultaneously in two mutually exclusive states: removed from the active set (cannot cast new votes) yet their accumulated vote weight remains live in the tally.

---

### Impact Explanation

A bridge value transfer of KAIA or ERC20 tokens can be executed with authorization from a deregistered (untrusted) operator. The most dangerous scenario is a security incident:

1. Operator A is compromised and votes on a malicious `handleKLAYTransfer` for nonce N (sending funds to an attacker-controlled address).
2. The owner deregisters A, believing this blocks the malicious transfer.
3. Any remaining active operator B votes on the same nonce N with the same parameters.
4. `voteCounts[voteKey]` reaches the threshold (A's stale vote + B's new vote), and the transfer executes — draining KAIA or ERC20 tokens from the bridge to the attacker.

The owner's remediation action is silently ineffective. This directly matches the allowed impact: *"Unauthorized transfer … affecting KAIA, bridged assets, or system-managed funds."* [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

The scenario requires: (a) an operator to vote on a nonce, (b) that operator to be deregistered, and (c) a second active operator to vote on the same nonce. In a multi-operator bridge with threshold ≥ 2, operators routinely vote on the same nonces as part of normal operation. A compromised-operator incident — the exact case where deregistration is used as a remediation — is precisely when this sequence occurs. Likelihood is **moderate to high** in a security-incident context.

---

### Recommendation

In `deregisterOperator()`, iterate over all open (non-closed) nonces and decrement the deregistered operator's vote contribution for each nonce they voted on. Concretely:

```solidity
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);
    delete operators[_operator];
    // Revoke outstanding votes for all open value-transfer nonces
    for (uint64 n = lowerHandleNonce; n <= upperHandleNonce; n++) {
        if (closedValueTransferVotes[n]) continue;
        VotesData storage vd = votes[uint8(VoteType.ValueTransfer)][n];
        bytes32 key = vd.voted[_operator];
        if (key != bytes32(0)) {
            vd.voteCounts[key]--;
            delete vd.voted[_operator];
        }
    }
    // Similarly revoke configuration votes for the current configurationNonce
    ...
    _removeFromOperatorList(_operator);
    emit OperatorDeregistered(_operator);
}
```

Alternatively, store a per-operator deregistration block number and reject stale votes in `_voteCommon` by checking whether the voter was still registered at the time of the vote.

---

### Proof of Concept

```
Setup:
  operators = [A, B, C], threshold = 2
  bridge holds 100 KAIA

Step 1: Operator A (compromised) calls handleKLAYTransfer(txHash, from, attacker, 100 KAIA, nonce=5, ...)
        → voteCounts[voteKey] = 1 (threshold not met, no transfer yet)

Step 2: Owner detects compromise, calls deregisterOperator(A)
        → operators[A] = false, operatorList shrinks
        → votes[0][5].voteCounts[voteKey] still = 1  ← stale vote persists

Step 3: Operator B (honest, unaware of A's intent) calls handleKLAYTransfer(same params, nonce=5)
        → _voteCommon: voteCounts[voteKey]++ → 2 >= threshold(2) → returns true
        → closedValueTransferVotes[5] = true
        → 100 KAIA transferred to attacker

Result: Bridge drained despite owner's remediation. A's deregistered vote counted.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L73-100)
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
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L134-174)
```text
    // registerOperator registers a new operator.
    function registerOperator(address _operator)
    external
    onlyOwner
    {
        require(operatorList.length < MAX_OPERATOR, "max operator limit");
        require(!operators[_operator], "exist operator");
        operators[_operator] = true;
        operatorList.push(_operator);
        emit OperatorRegistered(_operator);
    }

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-72)
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
```
