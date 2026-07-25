I found the key analog. Let me read the exact relevant sections of `BridgeOperator.sol` more carefully.

### Title
Deregistered Bridge Operator Votes Are Never Revoked, Enabling Unauthorized Asset Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator.deregisterOperator` removes an operator from the active set but does not clear that operator's outstanding votes from the `votes` storage mapping. A deregistered operator's vote count persists and can be combined with a subsequent vote from any remaining active operator to reach the threshold and execute a bridge value transfer — even though the owner deregistered the first operator specifically to prevent that transfer.

---

### Finding Description

`_voteValueTransfer` accumulates votes in `votes[VoteType.ValueTransfer][_requestNonce].voteCounts[voteKey]`, keyed by `keccak256(msg.data)`. When the accumulated count reaches `operatorThresholds[VoteType.ValueTransfer]`, the transfer executes immediately. [1](#0-0) 

`deregisterOperator` only deletes the operator from the `operators` mapping and splices them out of `operatorList`. It does **not** touch `votes[VoteType.ValueTransfer][*]` for any pending nonce: [2](#0-1) 

The code itself documents the consequence:

> *"Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered."* [3](#0-2) 

By contrast, `_voteConfiguration` is protected by a monotonically incrementing `configurationNonce` that is bumped on every successful vote, so stale configuration votes are automatically invalidated. No equivalent invalidation exists for value-transfer votes. [4](#0-3) 

The concrete execution paths that transfer assets are `handleKLAYTransfer` and `handleERC20Transfer`, both of which call `_voteValueTransfer` and then unconditionally send funds when it returns `true`: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

When the threshold is reached using a deregistered operator's stale vote, the bridge contract immediately transfers KLAY or ERC20 tokens to the `_to` address supplied in the call. The owner's deregistration action — intended to revoke authority — has no effect on already-cast votes. The corrupted value is the bridged asset balance: KLAY sent via `.call.value(_value)("")` or ERC20 tokens sent via `safeTransfer` / `mint`.

---

### Likelihood Explanation

The scenario requires:
1. A compromised or colluding operator (A) votes for a fraudulent `handleKLAYTransfer` / `handleERC20Transfer` call (attacker-controlled `_to`, inflated `_value`).
2. The bridge owner discovers the compromise and calls `deregisterOperator(A)`, believing the fraudulent vote is now void.
3. A second operator (B) — also compromised, or simply unaware — submits the identical call for the same `_requestedNonce`.
4. `_voteCommon` finds `voteCounts[voteKey] == 2 >= threshold`, returns `true`, and the transfer executes.

With a threshold of 2 and any two operators colluding (or one compromised and one deceived), this is reachable without majority-validator collusion. The bridge is a production service-chain component actively used for cross-chain asset movement.

---

### Recommendation

In `deregisterOperator`, iterate over all pending nonces and decrement (or zero out) the deregistered operator's vote contribution before removing them from the operator set:

```solidity
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);

    // Revoke all pending ValueTransfer votes cast by this operator.
    for (uint64 nonce = lowerHandleNonce; nonce <= upperHandleNonce; nonce++) {
        VotesData storage vd = votes[uint8(VoteType.ValueTransfer)][nonce];
        bytes32 key = vd.voted[_operator];
        if (key != bytes32(0)) {
            vd.voteCounts[key]--;
            delete vd.voted[_operator];
        }
    }

    delete operators[_operator];
    // ... splice operatorList as before ...
    emit OperatorDeregistered(_operator);
}
```

Alternatively, adopt the same sequential-nonce pattern used by `_voteConfiguration` for value-transfer votes, so that any operator change automatically invalidates all prior votes.

---

### Proof of Concept

Setup: threshold = 2, operators = {A, B, C}.

1. Operator A calls `handleKLAYTransfer(txHash, from, attacker, 1000 ether, nonce=5, blockNum, "")`.
   - `_voteValueTransfer(5)` → `voteCounts[keccak256(msg.data)] = 1` → returns `false`. No transfer yet.
2. Owner discovers A is compromised; calls `deregisterOperator(A)`.
   - `operators[A]` deleted. `operatorList` updated. **`votes[0][5]` untouched.**
3. Operator B (colluding or deceived) calls `handleKLAYTransfer(txHash, from, attacker, 1000 ether, nonce=5, blockNum, "")` with identical parameters.
   - `_voteValueTransfer(5)` → `voteCounts[same key]` increments to 2 ≥ threshold → returns `true`.
   - `closedValueTransferVotes[5] = true`.
   - `(bool ok,) = attacker.call.value(1000 ether)("")` executes.
   - **1000 KAIA transferred to attacker despite A being deregistered.**

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
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
