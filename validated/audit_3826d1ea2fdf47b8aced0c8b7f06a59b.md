Based on my investigation, I found a direct analog in the Kaia service-chain bridge contracts.

---

### Title
Bridge Ownership Transfer Does Not Revoke Deployer's Operator Privileges, Leaving New Owner Without Bridge Transfer Authority — (`contracts/service_chain/bridge/BridgeOperator.sol`)

### Summary

`BridgeOperator` registers `msg.sender` as an operator in its constructor and inherits `Ownable`'s `transferOwnership()`. After ownership is transferred to a new address, the old deployer address **remains a registered operator** while the new owner has **no operator privileges**. The new owner can manage the operator list but cannot vote on or execute bridge value transfers until they explicitly register themselves. Meanwhile, the old (deposed) operator retains the ability to unilaterally execute KAIA, ERC20, and ERC721 bridge transfers.

### Finding Description

In `BridgeOperator.sol`, the constructor unconditionally registers `msg.sender` as an operator:

```solidity
constructor() internal {
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        operatorThresholds[uint8(i)] = 1;
    }
    operators[msg.sender] = true;   // deployer becomes operator
    operatorList.push(msg.sender);
}
```

The contract inherits `Ownable`, which exposes `transferOwnership(address newOwner)`. When the owner transfers ownership:

- `newOwner` gains `onlyOwner` privileges (register/deregister operators, set thresholds).
- The **old deployer address is never removed from `operators`** — it remains a fully privileged operator.
- `newOwner` is **not added to `operators`** — it cannot call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` (all gated by `onlyOperators`).

The default `operatorThresholds[ValueTransfer] = 1`, so a single operator can unilaterally execute any bridge value transfer. The old deployer, still in the `operators` mapping, retains this unilateral power indefinitely until the new owner explicitly deregisters them — a step that is not enforced or prompted by the contract.

### Impact Explanation

The old (deposed) operator can:
1. Call `handleKLAYTransfer` to drain KAIA held by the bridge contract.
2. Call `handleERC20Transfer` to mint or transfer ERC20 tokens.
3. Call `handleERC721Transfer` to mint or transfer ERC721 tokens.

All three are gated only by `onlyOperators`, which the old deployer still satisfies. With threshold = 1, no other operator vote is needed.

Simultaneously, the new owner cannot execute any bridge transfers until they register themselves as an operator — a non-obvious step that the contract does not enforce or document at the point of ownership transfer.

This matches the M-11 invariant: the "credential" (operator registration) and the "ownership" (contract control) are decoupled. The new owner of the credential (contract ownership) has no operational purpose for bridge transfers; the old holder retains full operational authority.

### Likelihood Explanation

Ownership transfer is a standard operational action (e.g., handing a bridge over to a multisig or DAO). The deployer address being silently retained as an operator is non-obvious. Any operator key rotation or handover that uses `transferOwnership()` without also calling `deregisterOperator(oldOwner)` leaves the old key with live bridge transfer authority. The default threshold of 1 means no quorum is needed to exploit this.

### Recommendation

1. Override `transferOwnership()` (or add a `_beforeOwnershipTransfer` hook) to automatically deregister the outgoing owner from the `operators` mapping and register the incoming owner.
2. Alternatively, emit a warning event when ownership is transferred while the old owner is still a registered operator, so off-chain monitoring can detect the inconsistency.
3. Document clearly that `transferOwnership()` alone is insufficient for a full privilege handover and that `deregisterOperator` + `registerOperator` must be called atomically.

### Proof of Concept

```
1. Deploy Bridge (inherits BridgeOperator). Deployer = Alice.
   State: owner = Alice, operators = {Alice}, threshold[ValueTransfer] = 1

2. Alice calls transferOwnership(Bob).
   State: owner = Bob, operators = {Alice}, threshold[ValueTransfer] = 1

3. Alice (no longer owner) calls:
     bridge.handleKLAYTransfer(txHash, from, Alice, 1000 ether, nonce, blockNum, "")
   → passes onlyOperators (Alice still in operators mapping)
   → threshold = 1, Alice's vote alone closes the vote
   → 1000 KAIA transferred to Alice

4. Bob (new owner) attempts the same call:
   → reverts: "msg.sender is not an operator"
   → Bob has zero bridge transfer authority until he calls registerOperator(Bob)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol (L63-65)
```text
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }
```
