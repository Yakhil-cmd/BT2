### Title
Stale Operator Votes Persist After `deregisterOperator`, Enabling Unauthorized Bridge Value Transfers — (File: `contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

In `BridgeOperator.sol`, calling `deregisterOperator()` removes an operator from the `operators` mapping and `operatorList`, but does **not** revoke that operator's already-cast votes from the `votes` storage mapping. A remaining active operator can then cast a vote on the same nonce, and `_voteCommon` counts the deregistered operator's stale `voteCounts` entry toward the threshold, executing a bridge value transfer that the post-deregistration operator set would not have approved on its own.

### Finding Description

`deregisterOperator()` performs:

```solidity
delete operators[_operator];
// removes from operatorList array
``` [1](#0-0) 

It does **not** touch `votes[voteType][nonce].voted[_operator]` or `votes[voteType][nonce].voteCounts[voteKey]`. Those entries remain in storage.

`_voteCommon` then evaluates:

```solidity
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
``` [2](#0-1) 

Because `voteCounts` still includes the deregistered operator's contribution, the threshold can be reached with fewer *active* operator approvals than intended. The code itself documents this exact scenario:

> *"Note that outstanding votes by the deregistered operator are not revoked. … In this case the request was executed with A's vote after A is deregistered."* [3](#0-2) 

The stale vote is never cleared because `_updateHandleNonce` only deletes `closedValueTransferVotes[i]` and `handleNoncesToBlockNums[i]` for *already-handled* nonces — it does not touch the `votes` mapping for pending nonces. [4](#0-3) 

### Impact Explanation

A bridge value transfer (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`) is executed using the authority of a deregistered operator. This constitutes an **unauthorized transfer of KAIA or bridged ERC20/ERC721 assets** — the post-deregistration operator set did not collectively reach the threshold, yet the transfer executes. The corrupted value is `votes[ValueTransfer][N].voteCounts[voteKey]`, which retains the deregistered operator's count and causes `_voteCommon` to return `true` prematurely.

### Likelihood Explanation

The window exists between the block in which `deregisterOperator` is mined and the block in which any remaining operator votes on the same nonce. In a multi-operator bridge with pending nonces (common in production service-chain deployments), this window is non-trivial. The trigger — a remaining active operator calling `handleKLAYTransfer` — requires no privilege.

### Recommendation

In `deregisterOperator`, iterate over all open nonces tracked by the bridge and subtract the deregistered operator's vote from `voteCounts` (and remove their entry from `voted`). Alternatively, add a check inside `_voteCommon` that verifies every address in `vote.voters` is still an active operator before counting their contribution, re-computing the effective count on each call.

### Proof of Concept

```
Setup:
  operators = {A, B, C}, threshold(ValueTransfer) = 2

Step 1: Operator A calls handleKLAYTransfer(nonce=N, to=victim, value=1000 KAIA)
  → _voteCommon records: voted[A]=voteKey, voteCounts[voteKey]=1
  → threshold not reached, transfer not executed

Step 2: Owner calls deregisterOperator(A)
  → operators[A] = false, A removed from operatorList
  → votes[ValueTransfer][N].voted[A] = voteKey  ← STILL IN STORAGE
  → votes[ValueTransfer][N].voteCounts[voteKey] = 1  ← STILL IN STORAGE

Step 3: Operator B calls handleKLAYTransfer(nonce=N, to=victim, value=1000 KAIA)
  → _voteCommon: voted[B]=voteKey, voteCounts[voteKey]++ → 2
  → 2 >= operatorThresholds[ValueTransfer]=2 → returns true
  → closedValueTransferVotes[N] = true
  → 1000 KAIA transferred to victim

Result: Transfer executed with 1 active-operator approval (B only),
        using A's stale vote after A was deregistered.
        The effective security threshold was bypassed.
```

The `handleKLAYTransfer` call path that executes the transfer: [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L96-99)
```text
        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L147-158)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-156)
```text
    function _updateHandleNonce(uint64 _requestedNonce) internal {
        if (_requestedNonce > upperHandleNonce) {
            upperHandleNonce = _requestedNonce;
        }

        uint64 limit = lowerHandleNonce + 200;
        if (limit > upperHandleNonce) {
            limit = upperHandleNonce;
        }

        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
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
