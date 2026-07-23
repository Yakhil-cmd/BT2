### Title
USDT Fee-on-Transfer Permanently Breaks `swap` and `addLiquidity` Balance Checks in Any Pool Where USDT Is a Token — (`metric-core/contracts/MetricOmmPool.sol`, `metric-core/contracts/libraries/LiquidityLib.sol`)

---

### Summary

Both `swap` and `addLiquidity` use a "snapshot balance before callback, verify balance increased by exactly the owed amount after callback" pattern to enforce payment. When USDT's transfer fee is non-zero, the pool receives `amount − fee` instead of `amount`, causing the balance check to fail and the transaction to revert unconditionally. Every swap and every liquidity deposit in any pool whose token0 or token1 is USDT becomes permanently unusable the moment Tether enables its fee.

---

### Finding Description

**Swap path — `MetricOmmPool.sol`**

```
// zeroForOne branch (token0 is input)
uint256 balance0Before = balance0();                                    // line 257
IMetricOmmSwapCallback(msg.sender)
    .metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);   // line 258
if (amount0Delta > 0 && balance0Before + uint256(amount0Delta) > balance0()) {
    revert IncorrectDelta();                                            // line 261-263
}
```

The callback is expected to transfer exactly `amount0Delta` of token0 to the pool. If token0 is USDT with fee `f > 0`, the pool's actual balance increase is `amount0Delta − f`. The check becomes:

```
balance0Before + amount0Delta  >  balance0Before + amount0Delta − f
```

which is always `true` (since `f > 0`), so `IncorrectDelta` is always thrown. The identical pattern exists for the `!zeroForOne` branch at lines 271–277.

**addLiquidity path — `LiquidityLib.sol`**

```
uint256 balance0Before = IERC20(ctx.token0).balanceOf(address(this));  // line 145
uint256 balance1Before = IERC20(ctx.token1).balanceOf(address(this));  // line 146
IMetricOmmModifyLiquidityCallback(msg.sender)
    .metricOmmModifyLiquidityCallback(amount0Added, amount1Added, callbackData); // line 147-148
if (amount0Added > 0 && balance0Before + amount0Added > IERC20(ctx.token0).balanceOf(address(this))) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();            // line 149-151
}
if (amount1Added > 0 && balance1Before + amount1Added > IERC20(ctx.token1).balanceOf(address(this))) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();            // line 152-154
}
```

Same invariant, same failure mode: the callback sends `amount0Added` USDT, the pool receives `amount0Added − f`, the check fires, and the deposit reverts.

---

### Impact Explanation

Any pool whose `token0` or `token1` is USDT becomes completely non-functional for its primary operations:

- **`swap`** — every call reverts with `IncorrectDelta` when USDT is the input leg.
- **`addLiquidity`** — every call reverts with `InsufficientTokenBalance` when USDT is either token.
- **`removeLiquidity`** — transfers tokens out of the pool; the pool's balance decreases by the full `amount0Removed`, but the LP receives only `amount0Removed − fee`. The pool's internal `binTotals` accounting is decremented by the same scaled amount, so no insolvency divergence occurs here, but LPs silently lose the fee on every withdrawal.

The net result is that the pool is bricked for swaps and deposits — the two core revenue-generating operations — for as long as the USDT fee is non-zero.

---

### Likelihood Explanation

USDT's fee is currently set to zero on mainnet, but the fee mechanism is live in the deployed contract and can be enabled by Tether at any time. The contest scope explicitly carves USDT out of the "non-standard ERC20 behavior" exclusion, making this a valid in-scope trigger. No attacker action is required; the condition activates automatically if Tether enables the fee.

---

### Recommendation

Replace the strict equality balance check with a "received at least" check that measures the actual balance delta rather than assuming it equals the nominal transfer amount:

**Swap:**
```solidity
uint256 balance0Before = balance0();
IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
if (amount0Delta > 0 && balance0() < balance0Before + uint256(amount0Delta)) {
    revert IncorrectDelta();
}
```

**addLiquidity (LiquidityLib):**
```solidity
uint256 balance0Before = IERC20(ctx.token0).balanceOf(address(this));
uint256 balance1Before = IERC20(ctx.token1).balanceOf(address(this));
IMetricOmmModifyLiquidityCallback(msg.sender)
    .metricOmmModifyLiquidityCallback(amount0Added, amount1Added, callbackData);
if (amount0Added > 0 && IERC20(ctx.token0).balanceOf(address(this)) < balance0Before + amount0Added) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();
}
if (amount1Added > 0 && IERC20(ctx.token1).balanceOf(address(this)) < balance1Before + amount1Added) {
    revert IMetricOmmPoolActions.InsufficientTokenBalance();
}
```

Note: the condition direction is already logically equivalent (`a > b` ↔ `b < a`), but the current code uses `>` which reads as "expected > actual → revert", which is correct. The real fix is to ensure the pool's internal accounting (`binTotals.scaledToken0/1`) is updated to reflect the *actual* received amount rather than the nominal `amount0Added`, so that the pool does not record more tokens than it holds. Alternatively, document that USDT (with fee > 0) is not a supported pool token.

---

### Proof of Concept

1. Deploy a USDT/WETH pool via `MetricOmmPoolFactory.createPool` with `token0 = USDT`, `token1 = WETH`.
2. Add liquidity normally (fee = 0, succeeds).
3. Simulate Tether enabling a 1 bps fee on USDT transfers.
4. Call `pool.swap(recipient, true, 1000e6, 0, "", "")` (sell USDT for WETH).
   - Pool computes `amount0Delta = 1000e6` (USDT owed by caller).
   - Pool records `balance0Before = pool.balance0()`.
   - Pool calls `metricOmmSwapCallback(1000e6, -outAmount, "")`.
   - Callback calls `USDT.transfer(pool, 1000e6)`.
   - USDT deducts fee: pool receives `1000e6 − fee`.
   - Pool checks: `balance0Before + 1000e6 > balance0Before + 1000e6 − fee` → `true`.
   - Pool reverts: `IncorrectDelta`.
5. Call `pool.addLiquidity(owner, salt, deltas, "", "")`.
   - Pool calls `metricOmmModifyLiquidityCallback(amount0Added, amount1Added, "")`.
   - Callback transfers `amount0Added` USDT; pool receives `amount0Added − fee`.
   - Pool checks: `balance0Before + amount0Added > balance0Before + amount0Added − fee` → `true`.
   - Pool reverts: `InsufficientTokenBalance`.

Both core operations are permanently broken for the USDT pool. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L250-255)
```text
    if (zeroForOne) {
      if (amount1Delta < 0) {
        // casting to uint256 is safe because amount1Delta is negative and the ammount of tokens in pool is capped by uint128.max
        // forge-lint: disable-next-line(unsafe-typecast)
        transferToken1(recipient, uint256(-amount1Delta));
      }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L257-263)
```text
      uint256 balance0Before = balance0();
      IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
      // casting to uint256 is safe because amount0Delta is positive and the ammount of tokens in pool is capped by uint128.max
      // forge-lint: disable-next-line(unsafe-typecast)
      if (amount0Delta > 0 && balance0Before + uint256(amount0Delta) > balance0()) {
        revert IncorrectDelta();
      }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L271-277)
```text
      uint256 balance1Before = balance1();
      IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(amount0Delta, amount1Delta, callbackData);
      // casting to uint256 is safe because amount1Delta is positive and the ammount of tokens in pool is capped by uint128.max
      // forge-lint: disable-next-line(unsafe-typecast)
      if (amount1Delta > 0 && balance1Before + uint256(amount1Delta) > balance1()) {
        revert IncorrectDelta();
      }
```

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L144-154)
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
```
