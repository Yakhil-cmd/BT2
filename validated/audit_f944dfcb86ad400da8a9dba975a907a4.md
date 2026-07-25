### Title
Previous Bridge Owner Retains Operator Role After `transferOwnership`, Enabling Unauthorized Cross-Chain Value Transfer Approval — (File: `contracts/service_chain/bridge/BridgeOperator.sol`)

---

### Summary

`BridgeOperator` registers `msg.sender` as an operator in its constructor. When `transferOwnership` is called (inherited from `Ownable`), only the `_owner` storage slot is updated. The previous owner's entry in `operators[oldOwner]` and `operatorList` is never cleared. The previous owner retains the `onlyOperators` privilege indefinitely, allowing them to vote on and unilaterally approve fraudulent cross-chain value transfers.

---

### Finding Description

In `BridgeOperator.sol`, the constructor seeds the deployer as the sole operator:

```solidity
constructor() internal {
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        operatorThresholds[uint8(i)] = 1;
    }
    operators[msg.sender] = true;
    operatorList.push(msg.sender);
}
``` [1](#0-0) 

`transferOwnership` is inherited from OpenZeppelin's `Ownable` and only updates `_owner`:

```solidity
function _transferOwnership(address newOwner) internal {
    require(newOwner != address(0), "Ownable: new owner is the zero address");
    emit OwnershipTransferred(_owner, newOwner);
    _owner = newOwner;
}
``` [2](#0-1) 

`BridgeOperator` does not override `transferOwnership` to remove the old owner from `operators` or `operatorList`. After the transfer:

- The **new owner** holds `onlyOwner` privileges (register/deregister operators, set fee receiver) but is **not** an operator.
- The **old owner** loses `onlyOwner` privileges but **retains** `operators[oldOwner] == true` and remains in `operatorList`.

The `onlyOperators` modifier gates the bridge's value-transfer voting functions:

```solidity
modifier onlyOperators() {
    require(operators[msg.sender], "msg.sender is not an operator");
    _;
}
``` [3](#0-2) 

The default `operatorThresholds` for both `ValueTransfer` and `Configuration` vote types is `1`: [1](#0-0) 

With threshold = 1, a single operator vote is sufficient to execute a bridge request. The old owner, still recognized as an operator, can unilaterally call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` with fabricated parameters, causing the bridge to mint or unlock tokens on the destination chain without a corresponding legitimate source-chain event.

---

### Impact Explanation

The old owner can submit fraudulent bridge handle requests as a solo operator (threshold = 1 by default). Each successful vote mints or unlocks KLAY, ERC20, or ERC721 tokens on the destination chain. This is an **unauthorized mint/unlock of bridged assets** — a direct financial loss to the bridge's liquidity pool or token supply. The corrupted state (inflated token balances, drained bridge reserves) is persistent and affects all subsequent withdrawals and settlements.

---

### Likelihood Explanation

Ownership transfer is a routine administrative operation. The new owner has no on-chain signal that the old owner still holds operator status; the `OwnershipTransferred` event does not mention operators. Unless the new owner explicitly calls `deregisterOperator(oldOwner)` — a step not enforced or documented in the contract — the old owner's operator status persists indefinitely. Any bridge deployment that undergoes an ownership handover is affected.

---

### Recommendation

Override `transferOwnership` in `BridgeOperator` (or `BridgeTransfer`) to atomically remove the old owner from the operator set and optionally register the new owner:

```solidity
function transferOwnership(address newOwner) public onlyOwner {
    // Remove old owner from operator set
    if (operators[owner()]) {
        _deregisterOperator(owner());
    }
    super.transferOwnership(newOwner);
    // Optionally register new owner as operator
    if (!operators[newOwner]) {
        _registerOperator(newOwner);
    }
}
```

At minimum, document that callers must manually call `deregisterOperator(oldOwner)` before or immediately after `transferOwnership`.

---

### Proof of Concept

1. Alice deploys `Bridge`. Alice is `owner` and `operators[Alice] == true`, threshold = 1.
2. Alice calls `transferOwnership(Bob)`. Bob is now `owner`; `operators[Alice]` is still `true`.
3. Alice (no longer owner) calls `handleKLAYTransfer(fakeRequestTxHash, from, to, amount, fakeNonce, fakeBlockNum, extraData)` directly on the bridge.
4. `_voteValueTransfer` passes (`operators[Alice] == true`), vote count reaches threshold 1, `closedValueTransferVotes[fakeNonce] = true`, and the bridge transfers `amount` KLAY to `to` — minting or unlocking funds with no legitimate source-chain event.
5. Bob (new owner) is unaware unless he monitors `operatorList` and proactively calls `deregisterOperator(Alice)`. [4](#0-3) [5](#0-4)

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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol (L70-74)
```text
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L43-66)
```text
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfKLAY;

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            (bool ok, ) = feeReceiver.call.value(fee)("");
            require(ok, "transfer fee failed");

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                (bool ok, ) = msg.sender.call.value(feeRefund)("");
                require(ok, "refund fee failed");
            }

            return fee;
        }

        if (_feeLimit > 0) {
            (bool ok, ) = msg.sender.call.value(_feeLimit)("");
            require(ok, "refund fee failed");
        }
        return 0;
    }
```
