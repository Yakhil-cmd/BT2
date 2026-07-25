### Title
Bridge Operator Can Front-Run KLAY Fallback Transfers to Steal User Funds — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

The service-chain bridge's KLAY fallback function uses the live `feeOfKLAY` storage variable as both the fee and the fee-limit at execution time, with no upper bound on the fee and no delay on fee updates. A bridge operator (default threshold = 1) can front-run a pending user fallback transaction by raising `feeOfKLAY` to just below `msg.value`, causing the user to pay nearly their entire deposit as a fee while receiving almost nothing on the destination chain.

---

### Finding Description

`BridgeTransferKLAY.sol` exposes a payable fallback:

```solidity
// BridgeTransferKLAY.sol line 127-129
function () external payable {
    _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
}
```

`feeOfKLAY` is read at execution time and passed as `_feeLimit`. Inside `_requestKLAYTransfer`:

```solidity
// BridgeTransferKLAY.sol line 109, 118
require(msg.value > _feeLimit, "insufficient amount");
emit RequestValueTransfer(..., msg.value.sub(_feeLimit), ...);  // transferred amount
```

The amount bridged to the destination chain is `msg.value − feeOfKLAY`. The fee is then collected in `_payKLAYFeeAndRefundChange`:

```solidity
// BridgeFee.sol line 44, 47
uint256 fee = feeOfKLAY;
require(_feeLimit >= fee, "insufficient feeLimit");
```

Because `_feeLimit` was set to `feeOfKLAY` by the fallback, this check always passes regardless of how high the fee is. There is no cap on `feeOfKLAY` in `_setKLAYFee`:

```solidity
// BridgeFee.sol line 90-93
function _setKLAYFee(uint256 _fee) internal {
    feeOfKLAY = _fee;
    emit KLAYFeeChanged(_fee);
}
```

Fee changes take effect immediately with no timelock. The default configuration threshold is **1**, meaning a single operator can change the fee in one transaction:

```solidity
// BridgeOperator.sol line 54-57
constructor() internal {
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        operatorThresholds[uint8(i)] = 1;
    }
```

---

### Impact Explanation

An operator front-runs a user's fallback call by setting `feeOfKLAY` to `msg.value − 1 wei`. When the user's transaction executes:

- `feeLimit = feeOfKLAY = msg.value − 1`
- `require(msg.value > feeLimit)` → passes (by 1 wei)
- Fee paid to `feeReceiver` = `msg.value − 1`
- Amount bridged = `msg.value − feeLimit = 1 wei`

The operator (who controls `feeReceiver`) receives nearly the user's entire deposit. This is an **unauthorized transfer of KAIA from the user to the operator-controlled fee receiver**, matching the allowed impact gate.

---

### Likelihood Explanation

- Default `operatorThresholds[Configuration] = 1`: a single operator executes the fee change in one transaction with no co-signer required.
- No timelock or delay on `setKLAYFee`.
- No upper bound on `feeOfKLAY`.
- The fallback function is the natural entry point for simple KLAY bridge deposits (e.g., plain ETH sends).
- The operator can restore the fee immediately after the attack, leaving no persistent trace beyond the `KLAYFeeChanged` events.

---

### Recommendation

1. **Add a maximum fee cap** in `_setKLAYFee`, e.g., `require(_fee <= MAX_FEE)`.
2. **Add a minimum-received-amount parameter** to the fallback and `requestKLAYTransfer`, analogous to the `WithSlippage` instructions in the patched Solana program. Revert if `msg.value − feeOfKLAY < _minValue`.
3. **Increase the default configuration threshold** above 1 so that fee changes require multi-operator consensus.
4. **Add a timelock** on fee updates so users can observe and react to pending fee changes before they take effect.

---

### Proof of Concept

```
State before:
  feeOfKLAY = 0.1 KAIA
  feeReceiver = operator-controlled address

Step 1 (User):
  User submits fallback tx with msg.value = 1.1 KAIA
  (expecting to bridge 1.0 KAIA, pay 0.1 KAIA fee)

Step 2 (Operator, same block, higher gas / earlier in block):
  operator calls setKLAYFee(1.099999999999999999 KAIA, configNonce)
  → feeOfKLAY updated immediately (threshold=1, single operator)

Step 3 (User's fallback executes):
  feeLimit = feeOfKLAY = 1.099999999999999999 KAIA
  require(1.1 > 1.099999999999999999) → passes
  fee paid to feeReceiver = 1.099999999999999999 KAIA
  amount bridged = 1.1 - 1.099999999999999999 = 1 wei

Step 4 (Operator):
  operator calls setKLAYFee(0.1 KAIA, configNonce+1)
  → fee restored, attack concealed

Result:
  User loses ~1.0 KAIA to the operator-controlled feeReceiver.
  Only 1 wei is bridged to the destination chain.
```

**Affected files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-124)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");

        uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);

        emit RequestValueTransfer(
            TokenType.KLAY,
            msg.sender,
            _to,
            address(0),
            msg.value.sub(_feeLimit),
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L127-129)
```text
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
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

**File:** contracts/service_chain/bridge/BridgeFee.sol (L90-93)
```text
    function _setKLAYFee(uint256 _fee) internal {
        feeOfKLAY = _fee;
        emit KLAYFeeChanged(_fee);
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-57)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }
```
