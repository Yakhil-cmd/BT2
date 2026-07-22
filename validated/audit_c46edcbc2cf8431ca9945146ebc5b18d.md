### Title
Unused Native ETH Sent to Payable Liquidity Functions Is Permanently Stealable by Any Caller - (File: metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol)

---

### Summary

`addLiquidityExactShares` and `addLiquidityWeighted` in `MetricOmmPoolLiquidityAdder` are marked `payable` and consume native ETH via `PeripheryPayments.pay()` when the pool's WETH leg is involved. Neither function refunds unused ETH at the end of execution. Because `refundETH()` unconditionally sends the entire contract ETH balance to `msg.sender`, any ETH left in the contract after a user's transaction can be extracted by an arbitrary third party in a subsequent call.

---

### Finding Description

`PeripheryPayments.pay()` uses the contract's native ETH balance when `token == WETH`:

```solidity
// PeripheryPayments.sol lines 73-84
} else if (token == WETH) {
    uint256 nativeBalance = address(this).balance;
    if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
    } else if (nativeBalance > 0) {
        IWETH9(WETH).deposit{value: nativeBalance}();
        IERC20(WETH).safeTransfer(recipient, nativeBalance);
        IERC20(WETH).safeTransferFrom(payer, recipient, value - nativeBalance);
    } else {
        IERC20(WETH).safeTransferFrom(payer, recipient, value);
    }
}
```

When `nativeBalance >= value`, exactly `value` ETH is wrapped and forwarded; the surplus stays in the contract. None of the four `payable` entry points (`addLiquidityExactShares` ×2, `addLiquidityWeighted` ×2) call `refundETH()` before returning.

`refundETH()` is permissionless and sends the full balance to `msg.sender`:

```solidity
// PeripheryPayments.sol lines 58-63
function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
        _transferETH(msg.sender, balance);
    }
}
```

The `receive()` guard (`if (msg.sender != WETH) revert NotWETH()`) only applies to plain ETH transfers with no calldata; it does **not** block ETH sent alongside a function call to a `payable` selector. A user calling `addLiquidityWeighted{value: 1 ether}(...)` successfully deposits ETH into the contract.

The interface NatSpec acknowledges the pattern but treats it as a caller obligation rather than an on-chain invariant:

> *"unused ETH can be reclaimed via `refundETH` in the same multicall"*

No enforcement exists to ensure the user actually does so.

---

### Impact Explanation

Any ETH surplus left in `MetricOmmPoolLiquidityAdder` after a liquidity call is immediately claimable by any address via `refundETH()`. The victim loses the full surplus amount with no recourse. This is a direct loss of user principal with no protocol-side recovery path.

The `addLiquidityWeighted` path is the highest-risk entry point: the user cannot know the exact ETH required before the probe executes, so they must send up to `maxAmountToken0` (or `maxAmountToken1`) in ETH. The actual amount consumed is `amount0Delta ≤ maxAmountToken0`, leaving `maxAmountToken0 - amount0Delta` ETH stranded.

---

### Likelihood Explanation

- WETH-paired pools are a primary use case on Ethereum and Base.
- `addLiquidityWeighted` is the recommended path for users who do not know the exact deposit ratio upfront; sending a generous ETH cap is the natural usage.
- The attack requires only a single permissionless call (`refundETH()`) in a subsequent transaction; no special privileges, flash loans, or complex setup are needed.
- Users who call the function directly (not via `multicall`) — including integrators, scripts, and wallets that do not batch — are unconditionally vulnerable.

---

### Recommendation

Add an automatic ETH refund at the end of each payable liquidity entry point, mirroring the fix applied in the referenced external report:

```solidity
function addLiquidityWeighted(...) external payable override returns (...) {
    // ... existing logic ...
    // Refund any unused native ETH to the caller
    uint256 remaining = address(this).balance;
    if (remaining > 0) _transferETH(msg.sender, remaining);
}
```

Apply the same pattern to both overloads of `addLiquidityExactShares` and `addLiquidityWeighted`. The same fix should be evaluated for the `payable` swap functions in `MetricOmmSimpleRouter` (`exactInputSingle`, `exactInput`, `exactOutputSingle`, `exactOutput`), though the `IMetricOmmSimpleRouter` NatSpec already states "No native ETH" in scope, making those functions lower risk in practice.

---

### Proof of Concept

1. Pool has WETH as `token0`.
2. Alice calls `addLiquidityWeighted{value: 1 ether}(pool, salt, weightDeltas, 1 ether, 500e6, ...)`.
3. The probe determines `need0 = 0.7 ether`; shares are scaled accordingly.
4. The paying add runs; `pay(WETH, Alice, pool, 0.7 ether)` wraps and forwards 0.7 ETH.
5. `MetricOmmPoolLiquidityAdder` now holds 0.3 ETH.
6. Alice's transaction is mined. Bob observes the state on-chain.
7. Bob calls `refundETH()` → receives 0.3 ETH. Alice's surplus is permanently lost.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L56-68)
```text
  function addLiquidityExactShares(
    address pool,
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    uint256 maxAmountToken0,
    uint256 maxAmountToken1,
    bytes calldata extensionData
  ) external payable override returns (uint256 amount0Added, uint256 amount1Added) {
    _validateOwner(owner);
    _validateDeltas(deltas);
    return _addLiquidity(pool, owner, salt, deltas, msg.sender, maxAmountToken0, maxAmountToken1, extensionData);
  }
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L88-116)
```text
  function addLiquidityWeighted(
    address pool,
    address owner,
    uint80 salt,
    LiquidityDelta calldata weightDeltas,
    uint256 maxAmountToken0,
    uint256 maxAmountToken1,
    int8 minimalCurBin,
    uint104 minimalPosition,
    int8 maximalCurBin,
    uint104 maximalPosition,
    bytes calldata extensionData
  ) external payable override returns (uint256 amount0Added, uint256 amount1Added) {
    _validateOwner(owner);
    _validateDeltas(weightDeltas);
    _validatePositiveWeights(weightDeltas);
    _validateBinAndBinPosition(pool, minimalCurBin, minimalPosition, maximalCurBin, maximalPosition);

    try IMetricOmmPoolActions(pool)
      .addLiquidity(owner, salt, weightDeltas, abi.encode(KIND_PROBE), extensionData) returns (
      uint256, uint256
    ) {
      revert WeightedProbeInconclusive();
    } catch (bytes memory reason) {
      (uint256 need0, uint256 need1) = _decodeLiquidityProbeOrBubble(reason);
      LiquidityDelta memory scaled = _scaleWeightsToShares(weightDeltas, maxAmountToken0, maxAmountToken1, need0, need1);
      return _addLiquidity(pool, owner, salt, scaled, msg.sender, maxAmountToken0, maxAmountToken1, extensionData);
    }
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L58-63)
```text
  function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
      _transferETH(msg.sender, balance);
    }
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L73-84)
```text
    } else if (token == WETH) {
      uint256 nativeBalance = address(this).balance;
      if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
      } else if (nativeBalance > 0) {
        IWETH9(WETH).deposit{value: nativeBalance}();
        IERC20(WETH).safeTransfer(recipient, nativeBalance);
        IERC20(WETH).safeTransferFrom(payer, recipient, value - nativeBalance);
      } else {
        IERC20(WETH).safeTransferFrom(payer, recipient, value);
      }
```

**File:** metric-periphery/contracts/interfaces/IMetricOmmPoolLiquidityAdder.sol (L15-17)
```text
/// @dev Native ETH input uses the same multicall pattern as the swap router: send ETH with the add call (or
///      `multicall{value}`) when the pool's WETH leg is token0 or token1; unused ETH can be reclaimed via
///      `refundETH` in the same multicall.
```
