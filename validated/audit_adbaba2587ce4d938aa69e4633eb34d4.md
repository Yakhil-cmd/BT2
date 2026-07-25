I found a direct analog in `contracts/service_chain/bridge/BridgeOperator.sol`. The `deregisterOperator` function explicitly acknowledges in its own comments that stale votes from deregistered operators are not cleared. Let me verify the full contract and impact.

### Title
Stale Votes from Deregistered Bridge Operators Persist and Can Execute Unauthorized Value Transfers — (File: contracts/service_chain/bridge/BridgeOperator.sol)

### Summary

`BridgeOperator.deregisterOperator()` removes an operator from the authorized set but never clears that operator's outstanding votes from the `votes` storage mapping. A deregistered operator's `voteCounts` contribution persists indefinitely, so any remaining active operator voting on the same nonce can push the tally over the threshold and execute a value transfer (KAIA or bridged tokens) using the deregistered operator's stale vote. The contract's own comment at line 148 acknowledges this behavior but treats it as an operator-education problem rather than fixing it in code.

---

### Finding Description

`BridgeOperator` maintains per-nonce vote state in:

```solidity
struct VotesData {
    address[] voters;
    mapping(address => bytes32) voted;       // operator → voteKey
    mapping(bytes32 => uint8) voteCounts;    // voteKey → count
}
mapping(uint8 => mapping(uint64 => VotesData)) private votes;
``` [1](#0-0) 

When an operator is deregistered, only the `operators` mapping entry and the `operatorList` array entry are removed:

```solidity
function deregisterOperator(address _operator) external onlyOwner {
    require(operators[_operator]);
    delete operators[_operator];
    // operatorList swap-and-pop ...
    emit OperatorDeregistered(_operator);
}
``` [2](#0-1) 

Neither `votes[voteType][nonce].voted[_operator]` nor `votes[voteType][nonce].voteCounts[voteKey]` is touched. The stale `voteCounts` entry remains at its pre-deregistration value.

`_voteCommon` checks the threshold against the raw `voteCounts` value, which still includes the deregistered operator's contribution:

```solidity
vote.voteCounts[_voteKey]++;
if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
    return true;   // triggers execution
}
``` [3](#0-2) 

`_voteValueTransfer` then marks the nonce closed and returns `true`, causing the caller (the Bridge contract) to execute the cross-chain asset transfer:

```solidity
if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
    closedValueTransferVotes[_requestNonce] = true;
    return true;
}
``` [4](#0-3) 

The contract's own developer comment at lines 146–158 explicitly describes the scenario and defers responsibility to the owner:

> *"Note that outstanding votes by the deregistered operator are not revoked … The Owner shall recognize this issue and expect that operator deregistration takes some time to be fully effective."* [5](#0-4) 

This is not a mitigation — it is an unresolved invariant break documented in-code.

---

### Impact Explanation

The broken invariant is: **after `deregisterOperator(A)` returns, operator A must have zero influence over any future or pending vote outcome.**

Because `voteCounts` is not decremented, A's vote weight persists. A single remaining active operator can combine with A's stale vote to reach the threshold and execute a value transfer of KAIA or bridged ERC-20/ERC-721 tokens to an arbitrary address. This constitutes an unauthorized transfer of bridged assets — a direct match to the allowed impact gate ("Unauthorized transfer … affecting KAIA, bridged assets, or system-managed funds").

The owner's primary security response to a compromised or malicious operator — deregistration — is therefore not atomically effective. A window exists (from A's vote to the nonce being closed) during which A's authority is revoked on paper but still operative on-chain.

---

### Likelihood Explanation

The scenario requires:
1. An operator votes on a nonce before being deregistered (routine bridge operation).
2. The owner deregisters that operator (a normal administrative action, e.g., key rotation or compromise response).
3. Any remaining active operator votes on the same nonce.

Steps 1–3 are all individually normal operations. Their combination is not exotic; it is the expected sequence when an operator is rotated out mid-flight. The threshold is typically low (default 1, configurable up to `operatorList.length`), so a single colluding or independently acting operator suffices. The service-chain bridge is a production component used for cross-chain value transfer.

---

### Recommendation

In `deregisterOperator`, iterate over all open nonces for both `VoteType.ValueTransfer` and `VoteType.Configuration` and decrement `voteCounts` for any `voteKey` the deregistered operator voted on, then clear `voted[_operator]`. Alternatively, record a "deregistration epoch" per operator and reject stale votes cast before that epoch during threshold evaluation. At minimum, the threshold check in `_voteCommon` should verify that `msg.sender` (the current voter) is still a registered operator at the time of the check — but this alone does not retroactively remove the deregistered operator's already-counted vote.

---

### Proof of Concept

```
Setup: operators = {A, B, C}, threshold(ValueTransfer) = 2

1. Operator A calls handleRequestVT(nonce=7, dst=attacker, amount=1000 KAIA)
   → _voteValueTransfer(7) → _voteCommon: voteCounts[key7] = 1  (threshold not reached)

2. Owner calls deregisterOperator(A)
   → operators[A] = false, operatorList shrinks to {B, C}
   → votes[ValueTransfer][7].voteCounts[key7] still = 1  ← stale

3. Operator B calls handleRequestVT(nonce=7, dst=attacker, amount=1000 KAIA)
   → _voteValueTransfer(7) → _voteCommon: voteCounts[key7]++ = 2 >= threshold 2
   → closedValueTransferVotes[7] = true, returns true
   → Bridge executes: transfer 1000 KAIA to attacker

Result: value transfer executed using A's vote after A was deregistered.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L26-34)
```text
    struct VotesData {
        address[] voters;   // voter list for deleting voted map
        mapping(address => bytes32) voted; // <operator, sha3(type, args, nonce)>

        bytes32[] voteKeys; // voteKey list for deleting voteCounts map
        mapping(bytes32 => uint8) voteCounts; // <sha3(type, args, nonce), uint8>
    }

    mapping(uint8 => mapping (uint64 => VotesData)) private votes; // <voteType, <nonce, VotesData>
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L74-116)
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
