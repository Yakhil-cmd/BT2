### Title
`PeripheryPayments.pay()` consumes `address(this).balance` without caller-ownership check, allowing any user to drain stuck ETH via WETH-input swaps — (File: `metric-periphery/contracts/base/PeripheryPayments.sol`)

---

### Summary

The `pay()` helper in `PeripheryPayments` uses the router's total native ETH balance (`address(this).balance`) when settling a WETH-input swap, rather than only the ETH the current caller actually sent. Any ETH that accumulates in the router from prior users who sent excess `msg.value` and did not call `refundETH()` is silently consumed on behalf of the next caller, giving that caller a free (or partially-free) swap at the prior user's expense.

---

### Finding Description

`PeripheryPayments.pay()` contains the following branch for WETH-denominated payments:

```solidity
} else if (token == WETH) {
    uint256 nativeBalance = address(this).balance;   // ← total contract balance, not msg.value
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
``` [1](#0-0) 

`address(this).balance` is the **entire** ETH balance of the router, not the ETH contributed by the current transaction. ETH can accumulate in the router through multiple legitimate paths:

1. **Excess `msg.value` on swap functions** — `exactInputSingle`, `exactInput`, `exactOutputSingle`, `exactOutput` are all `external payable`. A user who sends `msg.value = 1 ETH` for a 0.5 ETH swap and omits a trailing `refundETH()` call leaves 0.5 ETH stranded. [2](#0-1) 

2. **ETH sent to non-consuming payable functions** — `unwrapWETH9` and `sweepToken` are `public payable` but neither reads nor refunds `msg.value`. Any ETH attached to these calls is silently retained. [3](#0-2) 

3. **Liquidity adder payable functions** — `addLiquidityExactShares` and `addLiquidityWeighted` are `external payable` but settle via ERC-20 pulls; any attached ETH is stranded in the same `PeripheryPayments` base. [4](#0-3) 

The `receive()` function is correctly restricted to WETH-only:

```solidity
receive() external payable {
    if (msg.sender != WETH) revert NotWETH();
}
``` [5](#0-4) 

This blocks direct ETH transfers, but does **not** prevent accumulation via the payable entry points above. Once ETH is stranded, the `pay()` branch unconditionally consumes it for the next WETH-input swap caller, regardless of who deposited it.

---

### Impact Explanation

- **Victim (prior user)**: loses the stranded ETH permanently — it is wrapped and forwarded to the pool on behalf of a different user.
- **Beneficiary (attacker)**: calls any WETH-input swap with `msg.value = 0`; the router's accumulated ETH covers the pool's payment demand, giving the attacker a fully or partially subsidised swap.
- The `MetricOmmPoolLiquidityAdder` inherits the same `PeripheryPayments` base and the same `pay()` logic, so the same drain is possible when `token0` or `token1` equals WETH. [6](#0-5) 

---

### Likelihood Explanation

Medium. Users who interact via raw calls (not multicall bundles) routinely omit `refundETH()`. The `unwrapWETH9` / `sweepToken` payable signatures are easy to accidentally fund. An attacker only needs to watch for a non-zero `address(router).balance` and immediately call a WETH-input swap with `msg.value = 0`.

---

### Recommendation

Replace the global `address(this).balance` read with the ETH actually provided by the current caller. The standard approach is to pass `msg.value` down through the call stack and use only that amount in `pay()`:

```solidity
// In pay(), replace:
uint256 nativeBalance = address(this).balance;
// With:
uint256 nativeBalance = msgValue; // passed from the top-level entry point
```

Alternatively, track `msg.value` in transient storage at the entry point and clear it after `pay()` consumes it, mirroring the existing transient-storage pattern used for callback context.

---

### Proof of Concept

1. **Setup**: Router holds 0 ETH. User A calls `exactInputSingle` with `tokenIn = WETH`, `amountIn = 0.5 ETH`, `msg.value = 1 ETH`. The swap callback fires; `pay()` reads `address(this).balance = 1 ETH ≥ 0.5 ETH`, wraps 0.5 ETH, sends WETH to pool. Remaining 0.5 ETH stays in router. User A does **not** call `refundETH()`.

2. **Attack**: Attacker calls `exactInputSingle` with `tokenIn = WETH`, `amountIn = 0.5 ETH`, `msg.value = 0`. The swap callback fires; `pay()` reads `address(this).balance = 0.5 ETH ≥ 0.5 ETH`, wraps 0.5 ETH from User A's stranded funds, sends WETH to pool. Attacker receives swap output at zero ETH cost.

3. **Result**: User A loses 0.5 ETH; attacker gains a free 0.5 ETH swap. The `pay()` path that would have pulled WETH from the attacker via `safeTransferFrom` is never reached. [7](#0-6)

### Citations

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L32-34)
```text
  receive() external payable {
    if (msg.sender != WETH) revert NotWETH();
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L37-55)
```text
  function unwrapWETH9(uint256 amountMinimum, address recipient) public payable override {
    uint256 balanceWETH = IERC20(WETH).balanceOf(address(this));
    if (balanceWETH < amountMinimum) revert InsufficientWETH(amountMinimum, balanceWETH);

    if (balanceWETH > 0) {
      IWETH9(WETH).withdraw(balanceWETH);
      _transferETH(recipient, balanceWETH);
    }
  }

  /// @inheritdoc IPeripheryPayments
  function sweepToken(address token, uint256 amountMinimum, address recipient) public payable override {
    uint256 balanceToken = IERC20(token).balanceOf(address(this));
    if (balanceToken < amountMinimum) revert InsufficientToken(token, amountMinimum, balanceToken);

    if (balanceToken > 0) {
      IERC20(token).safeTransfer(recipient, balanceToken);
    }
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L69-88)
```text
  function pay(address token, address payer, address recipient, uint256 value) internal {
    // If the payer is contract it means we are in the middle of a path. In the middle of a path we operate on ERC20 only.
    if (payer == address(this)) {
      IERC20(token).safeTransfer(recipient, value);
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
    } else {
      IERC20(token).safeTransferFrom(payer, recipient, value);
    }
  }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L67-86)
```text
  function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut) {
    _checkDeadline(params.deadline);
    uint128 priceLimitX64 = MetricOmmSwapPath.normalizePriceLimit(params.zeroForOne, params.priceLimitX64);

    _setNextCallbackContext(params.pool, CALLBACK_MODE_JUST_PAY, msg.sender, params.tokenIn);
    (int128 amount0Delta, int128 amount1Delta) = IMetricOmmPoolActions(params.pool)
      .swap(
        params.recipient,
        params.zeroForOne,
        MetricOmmSwapInputs.asAmountSpecifiedIn(params.amountIn),
        priceLimitX64,
        "",
        params.extensionData
      );
    int128 out = MetricOmmSwapResults.extractAmountOut(params.zeroForOne, amount0Delta, amount1Delta);
    amountOut = MetricOmmSwapInputs.int128ToUint128(out);
    if (amountOut < params.amountOutMinimum) revert InsufficientOutput(amountOut, params.amountOutMinimum);

    _clearExpectedCallbackPool();
  }
```

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

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L172-177)
```text
    if (amount0Delta > 0) {
      pay(token0, payer, msg.sender, amount0Delta);
    }
    if (amount1Delta > 0) {
      pay(token1, payer, msg.sender, amount1Delta);
    }
```
