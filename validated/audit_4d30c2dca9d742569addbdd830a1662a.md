### Title
Old Bridge Owner Retains Operator Privileges After `transferOwnership` — (File: `contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary
`BridgeOperator` automatically registers the deployer as an operator in its constructor. When `transferOwnership` is called, only the `_owner` storage variable is updated (via the inherited `Ownable` logic). The old owner's entry in the `operators` mapping and `operatorList` array is never cleared, leaving the old owner with full `onlyOperators` access to execute bridge value transfers and configuration votes indefinitely.

### Finding Description
In `BridgeOperator.sol`, the constructor unconditionally registers `msg.sender` as an operator:

```solidity
operators[msg.sender] = true;
operatorList.push(msg.sender);
``` [1](#0-0) 

`transferOwnership` is inherited unchanged from `Ownable.sol`, which only reassigns `_owner`:

```solidity
function _transferOwnership(address newOwner) internal {
    require(newOwner != address(0), "Ownable: new owner is the zero address");
    emit OwnershipTransferred(_owner, newOwner);
    _owner = newOwner;
}
``` [2](#0-1) 

`BridgeOperator` does not override `transferOwnership` to call `deregisterOperator` on the outgoing owner. After the transfer, `operators[oldOwner]` remains `true` and `oldOwner` remains in `operatorList`. The `onlyOperators` modifier therefore continues to pass for the old owner:

```solidity
modifier onlyOperators() {
    require(operators[msg.sender], "msg.sender is not an operator");
    _;
}
``` [3](#0-2) 

`deregisterOperator` is `onlyOwner`, so only the **new** owner can remove the old owner — but this is not automatic and is not enforced by the protocol. [4](#0-3) 

### Impact Explanation
With the default `operatorThresholds[ValueTransfer] = 1`, the old owner can unilaterally call any `onlyOperators` function on the bridge after ownership has been transferred. This includes:

- **`handleValueTransfer` / `handleKLAYTransfer`** — the old owner can vote to execute cross-chain value transfer requests, moving KAIA or bridged ERC-20/ERC-721 tokens out of the bridge contract to arbitrary recipients.
- **`setKLAYFee` / `setERC20Fee` / `setOperatorThreshold`** — the old owner can alter bridge configuration (fees, voting thresholds) via `_voteConfiguration`, potentially lowering the threshold to 1 to enable unilateral execution of all future requests.

The corrupted protected value is the bridge's locked asset balance: the old owner can drain bridged assets or manipulate the fee/threshold state that governs all future transfers. [5](#0-4) 

### Likelihood Explanation
The scenario is reachable by any party who previously held bridge ownership and whose ownership was transferred away — a realistic operational event (key rotation, protocol upgrade, hostile takeover of the deployer key). No privileged access beyond the old owner's retained operator entry is required. The default threshold of 1 means no collusion is needed.

### Recommendation
Override `transferOwnership` in `BridgeOperator` (or add a `_beforeOwnershipTransfer` hook) to automatically call `deregisterOperator(currentOwner)` before updating `_owner`. Alternatively, add a check in `_voteCommon` / `onlyOperators` that rejects callers who are no longer the current owner if they were registered solely by virtue of being the deployer.

### Proof of Concept
```
1. Owner A deploys Bridge → constructor executes:
       operators[ownerA] = true
       operatorList = [ownerA]

2. Owner A calls transferOwnership(ownerB):
       _owner = ownerB
       operators[ownerA] still == true   ← not cleared

3. Owner A calls handleValueTransfer(recipient, amount, nonce, ...):
       onlyOperators check: operators[ownerA] == true → passes
       _voteValueTransfer(nonce) → threshold 1 → closedValueTransferVotes[nonce] = true
       Bridge transfers `amount` of bridged tokens to `recipient`

4. New owner (Owner B) is unaware; bridge assets are drained.
   Owner B must explicitly call deregisterOperator(ownerA) to stop further abuse,
   but any transfers already executed cannot be reversed.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-61)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }

        operators[msg.sender] = true;
        operatorList.push(msg.sender);
    }
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L134-144)
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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol (L70-74)
```text
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
```
