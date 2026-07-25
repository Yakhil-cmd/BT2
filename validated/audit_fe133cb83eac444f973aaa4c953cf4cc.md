### Title
Transaction-Reordering Race on `setOperatorThreshold` Lets a Single Operator Execute Multi-Sig-Protected Bridge Transfers — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator.setOperatorThreshold` overwrites `operatorThresholds` unconditionally, exactly like ERC20 `approve` overwrites an allowance. `_voteCommon` reads the threshold at execution time, exactly like `transferFrom` reads the allowance at execution time. A malicious operator who observes a pending `setOperatorThreshold` call in the mempool can front-run it to execute bridge value-transfer requests that were supposed to require the new, higher threshold, draining bridged assets with only one signature instead of the intended N.

---

### Finding Description

`BridgeOperator.setOperatorThreshold` writes the new threshold directly to storage with no check of the current value or of in-flight votes:

```solidity
// contracts/service_chain/bridge/BridgeOperator.sol  line 177-185
function setOperatorThreshold(VoteType _voteType, uint8 _threshold)
external onlyOwner
{
    require(_threshold > 0, "zero threshold");
    require(operatorList.length >= _threshold, "bigger than num of operators");
    operatorThresholds[uint8(_voteType)] = _threshold;   // ← unconditional overwrite
    emit OperatorThresholdChanged(_voteType, _threshold);
}
```

`_voteCommon` reads `operatorThresholds` at the moment each `handleKLAYTransfer` / `handleERC20Transfer` call is mined, not at the moment the vote was cast:

```solidity
// contracts/service_chain/bridge/BridgeOperator.sol  line 96
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;
}
```

`_voteValueTransfer` (called by both handle functions) only guards against a *closed* nonce; it does not snapshot the threshold at vote-submission time:

```solidity
// contracts/service_chain/bridge/BridgeOperator.sol  line 107
require(!closedValueTransferVotes[_requestNonce], "closed vote");
```

The actual asset movement happens after the threshold check passes:

```solidity
// contracts/service_chain/bridge/BridgeTransferKLAY.sol  line 98
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
```

```solidity
// contracts/service_chain/bridge/BridgeTransferERC20.sol  line 69-72
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);
}
```

---

### Impact Explanation

A malicious operator can execute bridge value transfers (KLAY, ERC20, ERC721) that the bridge owner intended to protect with a higher multi-operator threshold. Concretely:

- The bridge owner raises the threshold from 1 → 2 to require two independent operators before any cross-chain transfer is released.
- Before that transaction is mined, a single operator front-runs it with `handleKLAYTransfer` (or `handleERC20Transfer`) for every pending request nonce.
- Each call passes `_voteCommon`'s threshold check while `operatorThresholds[ValueTransfer]` is still 1, so `closedValueTransferVotes[nonce]` is set to `true` and the KLAY/tokens are transferred out.
- After the owner's `setOperatorThreshold` is mined, all those nonces are already closed; the security upgrade is retroactively ineffective.

The corrupted protected value is `operatorThresholds[uint8(VoteType.ValueTransfer)]` — the bridge owner's intended security invariant (N-of-M approval) is violated, and bridged assets (KLAY or ERC20 tokens held by the bridge contract) are transferred with fewer approvals than intended.

---

### Likelihood Explanation

- Operators are semi-trusted (registered by the bridge owner) but the attack only requires one of them to be malicious or compromised.
- The attack window is a single block: the operator must submit `handleKLAYTransfer` / `handleERC20Transfer` with a gas price higher than the owner's `setOperatorThreshold` transaction.
- On Kaia's service-chain / parent-chain topology, the bridge operator node is always online and can trivially monitor the mempool for owner transactions.
- The code itself documents awareness of a related timing issue for `deregisterOperator` (votes cast by a deregistered operator are not revoked), but no analogous warning or mitigation exists for `setOperatorThreshold`.

---

### Recommendation

1. **Require current threshold to be zero before setting a non-zero value** (the standard ERC20 mitigation): require the caller to first set the threshold to 0 (or a sentinel), then set the new value. This forces any in-flight votes to be resolved before the threshold changes.

2. **Snapshot the threshold at vote-submission time**: store the threshold that was active when each operator cast their vote and compare against that snapshot in `_voteCommon`, rather than reading the live `operatorThresholds` value.

3. **Invalidate open votes on threshold change**: when `setOperatorThreshold` is called, clear all `VotesData` entries for open (non-closed) nonces of the affected `VoteType`, so that operators must re-vote under the new threshold.

4. **Add a time-lock or pending-vote guard**: refuse `setOperatorThreshold` if any value-transfer nonce has accumulated at least one vote but has not yet been closed.

---

### Proof of Concept

```
State: bridge holds 1000 KLAY; operatorThresholds[ValueTransfer] = 1; 
       pending cross-chain requests at nonces 5, 6, 7.

Block N (mempool):
  TX_owner : setOperatorThreshold(ValueTransfer, 2)   gasPrice = P

Attacker (operator A) observes TX_owner, submits with gasPrice > P:
  TX_A1 : handleKLAYTransfer(hash5, from, to, 300 KLAY, nonce=5, blk=X, "")
  TX_A2 : handleKLAYTransfer(hash6, from, to, 300 KLAY, nonce=6, blk=X, "")
  TX_A3 : handleKLAYTransfer(hash7, from, to, 400 KLAY, nonce=7, blk=X, "")

Block N execution order (TX_A1, TX_A2, TX_A3 mined before TX_owner):
  _voteValueTransfer(5): closedValueTransferVotes[5]=false ✓
    _voteCommon: voteCounts[voteKey]++ → 1 >= operatorThresholds[0]=1 → true
    closedValueTransferVotes[5] = true
    _to.call.value(300 KLAY) → 300 KLAY transferred ✓
  (same for nonces 6 and 7)

  TX_owner mines: operatorThresholds[ValueTransfer] = 2  (too late)

Result: 1000 KLAY transferred out with a single operator signature.
        Nonces 5,6,7 are closed; the threshold=2 requirement never applied.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L176-185)
```text
    // setOperatorThreshold sets the operator threshold.
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L61-100)
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
