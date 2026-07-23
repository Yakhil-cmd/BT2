### Title
Unconsumed Native ETH Stranded on Router After Partial-Fill Exact-Input Swap — (`metric-periphery/contracts/MetricOmmSimpleRouter.sol` / `metric-periphery/contracts/base/PeripheryPayments.sol`)

---

### Summary

When a user calls `exactInputSingle` with native ETH (WETH as `tokenIn`) and the pool partially fills the swap due to insufficient liquidity, the router's `pay` callback wraps only the actual consumed amount. The unconsumed ETH remainder is silently stranded on the router with no automatic refund, and any third party can immediately steal it by calling the public `refundETH()` helper.

---

### Finding Description

**Pool partial-fill mechanics**

`MetricOmmPool._swapToken0ForToken1SpecifiedInput` (and its mirror `_swapToken1ForToken0SpecifiedInput`) iterate over bins until `amountSpecifiedRemainingScaled == 0` or until liquidity is exhausted (`totalAvailableToken1Scaled == 0`, `HIGHEST_BIN` reached, or price limit hit). When the loop exits early the function returns only the *actually consumed* input:

```
return (amountInScaled - state.amountSpecifiedRemainingScaled, ...)
```

`_executeSwap` propagates this partial value directly into `amount0Delta` / `amount1Delta`, so the pool's `swap` callback receives a delta smaller than `amountSpecified`.

**Router callback pays only the partial delta**

`_justPayCallback` calls `pay(tokenToPay, payer, pool, extractPositiveAmount(amount0Delta, amount1Delta))`. When `tokenIn == WETH` and the router holds native ETH, `pay` wraps exactly `value` (the partial delta) and transfers it to the pool:

```solidity
uint256 nativeBalance = address(this).balance;
if (nativeBalance >= value) {
    IWETH9(WETH).deposit{value: value}();   // wraps only the partial amount
    IERC20(WETH).safeTransfer(recipient, value);
}
```

The remainder `msg.value − actualConsumed` is left as raw ETH on the router.

**`exactInputSingle` does not check for partial fills**

Unlike `exactInput` (multi-hop), which explicitly reverts on partial fills:

```solidity
if (amountInActual < amount) revert InvalidInputAmountAtHop(...);
```

`exactInputSingle` only checks `amountOut >= amountOutMinimum`. A partial fill that still produces output above the user's minimum passes silently, leaving the unconsumed ETH on the router.

**`refundETH` is public and attribution-free**

```solidity
function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
        _transferETH(msg.sender, balance);   // sends to whoever calls it
    }
}
```

Any address can call `refundETH` in a subsequent transaction and receive the stranded ETH.

---

### Impact Explanation

A user who calls `exactInputSingle{value: X}(amountIn: X, tokenIn: WETH)` directly (not via a multicall that includes `refundETH`) and whose swap is partially filled loses `X − actualConsumed` ETH to the next caller of `refundETH`. This is a direct, permanent loss of user principal with no recovery path for the victim.

---

### Likelihood Explanation

- Pools with thin liquidity (few or small bins) will partially fill large exact-input swaps.
- Users who call `exactInputSingle` directly (not via multicall) are the normal integration pattern for simple single-hop swaps; the interface is `external payable` and documented as a standalone entry point.
- An attacker can monitor the mempool for `exactInputSingle` calls with native ETH and front-run or back-run with `refundETH` to capture the stranded balance.
- The `amountOutMinimum` guard only protects users who set it to the *full-fill* expected output; any lower value (including 0) leaves the user exposed.

---

### Recommendation

Add a partial-fill check in `exactInputSingle` analogous to the one already present in `exactInput`:

```solidity
int128 amountInActual = MetricOmmSwapResults.extractAmountIn(params.zeroForOne, amount0Delta, amount1Delta);
if (amountInActual < int128(params.amountIn)) revert PartialFill(amountInActual, params.amountIn);
```

Alternatively, after the swap, automatically refund any remaining native ETH balance to `msg.sender` inside `exactInputSingle` before returning, so stranded ETH cannot accumulate on the router.

---

### Proof of Concept

1. Pool `P` has only 0.5 WETH of token1 liquidity; Alice wants to swap 1 ETH for token1.
2. Alice calls `router.exactInputSingle{value: 1 ether}(ExactInputSingleParams({pool: P, tokenIn: WETH, amountIn: 1 ether, amountOutMinimum: 0, ...}))`.
3. `_executeSwap` → `_swapToken0ForToken1SpecifiedInput` exhausts all token1 liquidity after consuming 0.5 ETH; returns `amountInScaled = 0.5 ETH scaled`, `amountOutScaled = all token1`.
4. Pool calls `metricOmmSwapCallback(amount0Delta=0.5e18, amount1Delta=−allToken1, ...)`.
5. `_justPayCallback` → `pay(WETH, alice, pool, 0.5e18)` wraps 0.5 ETH; 0.5 ETH remains on the router.
6. `amountOut >= amountOutMinimum (0)` → no revert; `exactInputSingle` returns successfully.
7. Bob calls `router.refundETH()` in the next transaction; receives Alice's 0.5 ETH.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L683-703)
```text
      if (amountSpecified > 0) {
        if (zeroForOne) {
          // forge-lint: disable-next-line(unsafe-typecast)
          uint256 amountInScaled = TOKEN_0_SCALE_MULTIPLIER * uint256(amountSpecified);
          uint256 amountOutScaled;
          (amountInScaled, amountOutScaled, protocolFeeScaled) =
            _swapToken0ForToken1SpecifiedInput(amountInScaled, params);
          // forge-lint: disable-next-line(unsafe-typecast)
          amount0DeltaScaled = int256(amountInScaled);
          // forge-lint: disable-next-line(unsafe-typecast)
          amount1DeltaScaled = -int256(amountOutScaled);
        } else {
          // forge-lint: disable-next-line(unsafe-typecast)
          uint256 amountInScaled = TOKEN_1_SCALE_MULTIPLIER * uint256(amountSpecified);
          uint256 amountOutScaled;
          (amountInScaled, amountOutScaled, protocolFeeScaled) =
            _swapToken1ForToken0SpecifiedInput(amountInScaled, params);
          // forge-lint: disable-next-line(unsafe-typecast)
          amount0DeltaScaled = -int256(amountOutScaled);
          // forge-lint: disable-next-line(unsafe-typecast)
          amount1DeltaScaled = int256(amountInScaled);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1154-1162)
```text
      while (state.amountSpecifiedRemainingScaled > 0) {
        bool nonEmptyBin = true;
        if (binState.token1BalanceScaled == 0 || curPosInBinCache == 0) {
          if (params.priceLimitX64 != 0 && params.priceLimitX64 >= lowerPriceX64) {
            break;
          }
          if (totalAvailableToken1Scaled == 0) {
            break;
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

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L113-115)
```text

      int128 amountInActual = MetricOmmSwapResults.extractAmountIn(zeroForOne, amount0Delta, amount1Delta);
      if (amountInActual < amount) revert InvalidInputAmountAtHop(uint8(i), amountInActual, amount);
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L192-199)
```text
  function _justPayCallback(int256 amount0Delta, int256 amount1Delta) private {
    pay(
      _getTokenToPay(),
      _getPayer(),
      msg.sender,
      uint256(MetricOmmSwapResults.extractPositiveAmount(amount0Delta, amount1Delta))
    );
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L57-63)
```text
  /// @inheritdoc IPeripheryPayments
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
