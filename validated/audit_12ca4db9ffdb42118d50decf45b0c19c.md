### Title
Fee-on-Transfer USDT Activation Permanently DoS-es `addLiquidity` and `swap` — (File: `metric-core/contracts/libraries/LiquidityLib.sol`, `metric-core/contracts/MetricOmmPool.sol`)

### Summary

Both `addLiquidity` (in `LiquidityLib`) and `swap` (in `MetricOmmPool`) use a callback-then-balance-check pattern that requires the pool's token balance to increase by **at least** the pre-computed amount. USDT — which is explicitly deployed as a pool token across Ethereum, Optimism, BSC, and Linea — contains a dormant fee-on-transfer mechanism. If that mechanism is ever activated, every `addLiquidity` and `swap` call on any USDT pool will revert unconditionally, permanently bricking those pools.

### Finding Description

**`LiquidityLib.addLiquidity`** computes `amount0Added` / `amount1Added`, snapshots balances, fires the callback, then enforces:

```solidity
// LiquidityLib.sol lines 149-154
if (amount0Added > 0 && balance0Before + amount0Added > IERC20(ctx.token0).balanceOf(address(this))) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();
}
if (amount1Added > 0 && balance1Before + amount1Added > IERC20(ctx.token1).balanceOf(address(this))) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();
}
``` [1](#0-0) 

The callback is told to transfer exactly `amount0Added`. If USDT charges a fee on that transfer, the pool receives `amount0Added − fee`. The invariant `balance0Before + amount0Added ≤ balance0After` then fails because `balance0After = balance0Before + amount0Added − fee`, making the left side strictly greater. The call reverts with `InsufficientTokenBalance`.

**`MetricOmmPool.swap`** has the identical pattern for both swap directions:

```solidity
// MetricOmmPool.sol lines 257-263 (zeroForOne)
uint256 balance0Before = balance0();
IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
if (amount0Delta > 0 && balance0Before + uint256(amount0Delta) > balance0()) {
    revert IncorrectDelta();
}

// MetricOmmPool.sol lines 271-277 (!zeroForOne)
uint256 balance1Before = balance1();
IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
if (amount1Delta > 0 && balance1Before + uint256(amount1Delta) > balance1()) {
    revert IncorrectDelta();
}
``` [2](#0-1) 

Both checks fail identically when the input token is fee-on-transfer.

Additionally, `removeLiquidity` calls `safeTransfer(owner, amount0Removed)` without a balance guard:

```solidity
// LiquidityLib.sol lines 242-247
if (amount0Removed > 0) {
    IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
}
``` [3](#0-2) 

Here the pool's internal accounting decreases by `amount0Removed` but the LP only receives `amount0Removed − fee`, causing a silent loss of principal on every withdrawal.

### Impact Explanation

If USDT enables its fee-on-transfer mechanism:

- **`addLiquidity` reverts** on every call → LPs cannot deposit into any USDT pool.
- **`swap` reverts** on every call → traders cannot execute any trade in any USDT pool.
- **`removeLiquidity` silently underpays** → LPs lose the fee amount on every withdrawal.

The pool becomes completely non-functional for its two primary operations. Existing LP positions are trapped (they can withdraw but receive less than their accounting entitlement). No admin action or pause/unpause can recover the pool without a contract upgrade.

### Likelihood Explanation

USDT is explicitly configured as a pool token across multiple production networks:

- Ethereum: `0xdAC17F958D2ee523a2206206994597C13D831ec7` (USDT/USDC pair)
- Optimism: `0x94b008aA00579c1307B0EF2c499aD98a8ce58e58` (USDT/USDC pair)
- BSC: `0x55d398326f99059fF775485246999027B3197955` (multiple USDT pairs) [4](#0-3) [5](#0-4) 

USDT's contract has contained a fee-on-transfer switch since its inception. The contest scope explicitly includes USDC/USDT non-standard behavior. The likelihood of activation is low but non-zero, and the consequence is total pool failure.

### Recommendation

Replace the fixed-amount balance check with an actual-delta measurement:

```solidity
uint256 balance0After = IERC20(ctx.token0).balanceOf(address(this));
uint256 actualReceived0 = balance0After - balance0Before;
if (amount0Added > 0 && actualReceived0 < amount0Added) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();
}
// Use actualReceived0 for bin accounting instead of amount0Added
```

Apply the same pattern in `MetricOmmPool.swap`. For `removeLiquidity`, measure the balance before and after the transfer and emit the actual amount sent. Alternatively, add an explicit check in `createPool` that rejects tokens with known fee-on-transfer behavior.

### Proof of Concept

1. A USDT/USDC pool is deployed on Ethereum (as per the existing deployment config).
2. Tether Ltd. activates USDT's fee-on-transfer at 1 basis point.
3. LP calls `addLiquidity` via the router for 1,000,000 USDT.
4. `LiquidityLib.addLiquidity` computes `amount0Added = 1_000_000`.
5. Pool snapshots `balance0Before`.
6. Pool calls `metricOmmModifyLiquidityCallback(1_000_000, …)`.
7. Callback calls `USDT.safeTransfer(pool, 1_000_000)` — USDT deducts 100 as fee; pool receives 999,900.
8. Pool checks: `balance0Before + 1_000_000 > balance0Before + 999_900` → **TRUE** → reverts `InsufficientTokenBalance`.
9. Every subsequent `addLiquidity` and `swap` call reverts identically. The pool is permanently bricked.

### Citations

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L144-155)
```text
      if (amount0Added > 0 || amount1Added > 0) {
        uint256 balance0Before = IERC20(ctx.token0).balanceOf(address(this));
        uint256 balance1Before = IERC20(ctx.token1).balanceOf(address(this));
        IMetricOmmModifyLiquidityCallback(msg.sender)
          .metricOmmModifyLiquidityCallback(amount0Added, amount1Added, callbackData);
        if (amount0Added > 0 && balance0Before + amount0Added > IERC20(ctx.token0).balanceOf(address(this))) {
          revert IMetricOmmPoolActions.InsufficientTokenBalance();
        }
        if (amount1Added > 0 && balance1Before + amount1Added > IERC20(ctx.token1).balanceOf(address(this))) {
          revert IMetricOmmPoolActions.InsufficientTokenBalance();
        }
      }
```

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L242-247)
```text
      if (amount0Removed > 0) {
        IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
      }
      if (amount1Removed > 0) {
        IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
      }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L257-277)
```text
      uint256 balance0Before = balance0();
      IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
      // casting to uint256 is safe because amount0Delta is positive and the ammount of tokens in pool is capped by uint128.max
      // forge-lint: disable-next-line(unsafe-typecast)
      if (amount0Delta > 0 && balance0Before + uint256(amount0Delta) > balance0()) {
        revert IncorrectDelta();
      }
    } else {
      if (amount0Delta < 0) {
        // casting to uint256 is safe because amount0Delta is negative and the ammount of tokens in pool is capped by uint128.max
        // forge-lint: disable-next-line(unsafe-typecast)
        transferToken0(recipient, uint256(-amount0Delta));
      }

      uint256 balance1Before = balance1();
      IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
      // casting to uint256 is safe because amount1Delta is positive and the ammount of tokens in pool is capped by uint128.max
      // forge-lint: disable-next-line(unsafe-typecast)
      if (amount1Delta > 0 && balance1Before + uint256(amount1Delta) > balance1()) {
        revert IncorrectDelta();
      }
```

**File:** smart-contracts-poc/script/js/config/optimism/feeds/default.json (L1-10)
```json
{
  "oracle": "0x0000000000000000000000000000000000000000",
  "tokens": [
    {
      "pythLazerId": 8,
      "baseTokenSymbol": "USDT",
      "quoteTokenSymbol": "USDC",
      "baseTokenAddress": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58",
      "quoteTokenAddress": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"
    },
```

**File:** smart-contracts-poc/script/js/config/bsc/feeds/default.json (L91-94)
```json
      "quoteTokenSymbol": "USDT",
      "baseTokenAddress": "0x8fF795a6F4D97E7887C79beA79aba5cc76444aDf",
      "quoteTokenAddress": "0x55d398326f99059fF775485246999027B3197955"
    },
```
