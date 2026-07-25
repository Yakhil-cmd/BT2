### Title
`deregisterOperator` Lacks Threshold-Floor Guard, Allowing Bridge Owner to Render Value-Transfer Voting Permanently Unreachable — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.setOperatorThreshold` enforces `require(operatorList.length >= _threshold)` to prevent the threshold from exceeding the operator count. The symmetric guard is absent from `deregisterOperator`: removing operators can silently drop `operatorList.length` below the existing threshold for `VoteType.ValueTransfer` or `VoteType.Configuration`, making it arithmetically impossible for `_voteCommon` to ever return `true`. All pending and future cross-chain value-transfer requests (KAIA, ERC20, ERC721) are then permanently unprocessable until the owner manually corrects the configuration — and if the owner also renounces ownership, the bridge is irrecoverably locked.

### Finding Description

`setOperatorThreshold` enforces the invariant `operatorList.length >= _threshold`:

```solidity
// BridgeOperator.sol L181-182
require(_threshold > 0, "zero threshold");
require(operatorList.length >= _threshold, "bigger than num of operators");
```

`deregisterOperator` has no corresponding guard:

```solidity
// BridgeOperator.sol L159-174
function deregisterOperator(address _operator) external onlyOwner {
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

`_voteCommon` executes a value transfer only when accumulated votes reach the threshold:

```solidity
// BridgeOperator.sol L96-98
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
```

If `operatorList.length` is reduced below `operatorThresholds[VoteType.ValueTransfer]`, the condition can never be satisfied regardless of how many remaining operators vote, because the maximum achievable `voteCounts` equals the remaining operator count.

### Impact Explanation

`handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` all call `_voteValueTransfer` → `_voteCommon`. If the threshold is unreachable, every call returns `false` and the actual transfer is never executed. KAIA and bridged tokens deposited on the counterpart chain accumulate as unprocessable requests. If the owner subsequently calls `renounceOwnership()`, no one can call `setOperatorThreshold` or `registerOperator` to recover, making the lock permanent and all bridge-held assets irrecoverable.

### Likelihood Explanation

The bridge owner is a semi-trusted role expected to manage operators. The asymmetry between `setOperatorThreshold` (guarded) and `deregisterOperator` (unguarded) is a natural footgun: an operator rotation that removes an old operator before adding a new one, or a threshold increase followed by an operator reduction, silently violates the invariant. The existing comment in the code already acknowledges non-obvious deregistration side-effects, indicating the function is error-prone.

### Recommendation

Add a threshold-floor check inside `deregisterOperator` for every vote type before shrinking `operatorList`:

```solidity
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);
    uint newLen = operatorList.length - 1;
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        require(newLen >= operatorThresholds[i], "below threshold");
    }
    delete operators[_operator];
    // ... existing removal logic ...
}
```

Alternatively, enforce a minimum operator count of 1 and require the owner to lower the threshold before deregistering.

### Proof of Concept

1. Deploy `Bridge` (which inherits `BridgeOperator`). Owner `O` is the sole operator; `operatorThresholds[ValueTransfer] = 1`.
2. `O` registers operator `A`: `operatorList = [O, A]`.
3. `O` raises threshold: `setOperatorThreshold(ValueTransfer, 2)` — succeeds because `2 >= 2`.
4. `O` deregisters itself: `deregisterOperator(O)` — succeeds with no threshold check; `operatorList = [A]`, threshold still `2`.
5. `A` calls `handleKLAYTransfer(...)` for a pending cross-chain request. `_voteCommon` increments `voteCounts` to `1`, checks `1 >= 2` → `false`. Transfer never executes.
6. `A` calls `handleKLAYTransfer(...)` again (same nonce, same data). `_voteCommon` sees `oldVoteKeyOfVoter != 0`, decrements the old count, re-increments — still `1 >= 2` → `false`.
7. No further operators exist to cast a second vote. All value-transfer requests for KAIA locked in the bridge are permanently stuck. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L94-99)
```text
        vote.voteCounts[_voteKey]++;

        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L177-185)
```text
    function setOperatorThreshold(VoteType _voteType, uint8 _threshold)
    external
    onlyOwner
    {
        require(_threshold > 0, "zero threshold");
        require(operatorList.length >= _threshold, "bigger than num of operators");
        operatorThresholds[uint8(_voteType)] = _threshold;
        emit OperatorThresholdChanged(_voteType, _threshold);
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
