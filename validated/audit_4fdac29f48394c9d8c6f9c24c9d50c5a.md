### Title
Deregistered Bridge Operator Votes Persist and Can Satisfy the Threshold — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator._voteCommon` only validates that the **current caller** (`msg.sender`) is a registered operator at the moment of the call, but never invalidates or subtracts votes already cast by **subsequently deregistered** operators. A deregistered operator's vote count entry remains in `votes[voteType][nonce].voteCounts`, so a single currently-registered operator can push the tally over the threshold by combining their fresh vote with the stale vote of a removed operator, causing `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` to execute and release bridged assets.

### Finding Description

`BridgeOperator.sol` maintains a per-nonce vote tally in `votes[uint8(_voteType)][_nonce]`. The `onlyOperators` modifier gates entry to the handle functions, so only a currently-registered operator can call them. However, the threshold check inside `_voteCommon` counts **all** accumulated votes for a given `voteKey`, regardless of whether the original voters are still registered:

```solidity
vote.voteCounts[_voteKey]++;

if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
``` [1](#0-0) 

`deregisterOperator` removes the address from `operators` and `operatorList`, but performs **no cleanup** of the operator's existing vote entries:

```solidity
delete operators[_operator];
// operatorList shrink only — no vote cleanup
``` [2](#0-1) 

The code itself documents the consequence:

> "Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered." [3](#0-2) 

This is the direct analog of the ERC1404 `detectTransferRestriction` bug: the system validates only the **active party** (current `msg.sender` operator) but ignores the **inactive party** (deregistered operator whose vote is still counted).

The handle functions that release assets all flow through `_voteValueTransfer` → `_voteCommon`: [4](#0-3) [5](#0-4) 

### Impact Explanation

When the threshold is 2 and there are operators A, B, C:

1. Operator A votes on request nonce N — `voteCounts[voteKey]` = 1.
2. Owner deregisters A — A can no longer call handle functions, but `voteCounts[voteKey]` remains 1.
3. Operator B votes on nonce N with identical calldata — `voteCounts[voteKey]` reaches 2 ≥ threshold.
4. `closedValueTransferVotes[N]` is set to `true` and the bridge releases KAIA / ERC-20 / ERC-721 to `_to`.

The net effect is that a bridge value transfer is authorized with only **one** currently-trusted operator vote, violating the multi-operator threshold invariant. The corrupted value is `voteCounts[voteKey]`, which includes a contribution from a principal that the owner has explicitly revoked.

### Likelihood Explanation

The trigger requires only a single currently-registered operator to vote on a nonce that already carries a stale vote from a deregistered operator. This is a realistic operational scenario: operators are deregistered when they are compromised or leave the GC, precisely the moment when their outstanding votes should be invalidated. The window between deregistration and the stale vote being "used up" by a co-voter is unbounded.

### Recommendation

When `deregisterOperator` is called, iterate over all open (non-closed) vote nonces and decrement `voteCounts` for any `voteKey` the deregistered operator has voted on, then clear `vote.voted[_operator]`. Alternatively, record the block number at which each operator was deregistered and reject vote contributions from operators whose registration was revoked before the vote was cast.

### Proof of Concept

```
Setup: threshold = 2, operators = {owner, A, B}

1. A calls handleKLAYTransfer(txHash, from, to, value, nonce=5, ...)
   → _voteValueTransfer(5) → _voteCommon: voteCounts[keccak256(msg.data)] = 1
   → threshold not met, returns false, no transfer.

2. Owner calls deregisterOperator(A).
   → operators[A] = false; operatorList shrinks.
   → voteCounts[keccak256(calldata_for_nonce5)] still = 1.

3. B calls handleKLAYTransfer(txHash, from, to, value, nonce=5, ...)  ← identical calldata
   → onlyOperators: operators[B] = true ✓
   → _voteValueTransfer(5) → _voteCommon: voteCounts[voteKey]++ → 2 ≥ threshold
   → closedValueTransferVotes[5] = true
   → _to.call.value(value)("") executes — bridge releases funds.

Result: transfer authorized with only 1 currently-trusted operator (B),
        using A's stale vote after A was deregistered.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L91-99)
```text
        if (vote.voteCounts[_voteKey] == 0) {
            vote.voteKeys.push(_voteKey);
        }
        vote.voteCounts[_voteKey]++;

        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
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
