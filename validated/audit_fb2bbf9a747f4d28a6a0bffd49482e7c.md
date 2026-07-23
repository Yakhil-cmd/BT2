The key facts are now confirmed. Let me verify the reentrancy guard behavior to complete the analysis.

All the facts are confirmed. Here is the analysis:

**Key findings:**

1. `setPoolBinAdditionalFees` → `setBinAdditionalFees` has **zero cap validation** on `addFeeBuyE6`/`addFeeSellE6` (max value `uint16.max` = 65535 = ~6.55% in E6 units). [1](#0-0) 

2. By contrast, `setPoolAdminFees` enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps. [2](#0-1) 

3. During every swap, `binState.addFeeBuyE6` / `addFeeSellE6` are read from storage and added directly to `baseFeeX64` with no ceiling. [3](#0-2) [4](#0-3) [5](#0-4) 

4. The `MetricReentrancyGuardTransient` stores a single action ID in transient storage; `_nonReentrantBeforeView()` reverts if `_currentAction() != 0`, so `setBinAdditionalFees` **cannot** be called while a swap is active in the same transaction — the reentrancy path is blocked. [6](#0-5) 

5. The sandwich (front-run) path is a **separate transaction** and is not blocked by any guard. The admin can raise `addFeeBuyE6` to `uint16.max` before a trader's swap lands, then reset it.

6. `getSellAndBuyPrices()` and `MetricOmmPoolDataProvider` both read `addFeeBuyE6`/`addFeeSellE6` from storage to compute quotes, so a quote obtained before the admin's front-run will not reflect the elevated fee. [7](#0-6) 

**Verdict on the claim's framing:**

The claim is **substantively correct** that there is no cap on bin additional fees and that a pool admin can raise them to `uint16.max` (6.55%) without restriction, causing a trader to receive less output than quoted. However, the mechanism is a **sandwich (front-run across two transactions)**, not reentrancy — the reentrancy path is definitively blocked by the transient guard.

The pool admin is explicitly "semi-trusted only inside caps and timelocks" per the contest scope rules, and the absence of a cap on `setPoolBinAdditionalFees` while `setPoolAdminFees` is capped is a code-level admin-boundary break, not a "trusted admin" assumption.

---

### Title
Pool admin can bypass fee caps via uncapped `setPoolBinAdditionalFees`, enabling sandwich attacks that cause traders to receive less output than quoted — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with no cap validation, while the parallel `setPoolAdminFees` path enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to `uint16.max` (65535 = ~6.55% in E6) on any bin, including the currently active bin, and sandwich a trader's swap to extract value.

### Finding Description
`setPoolAdminFees` enforces `newAdminSpreadFeeE6 > maxAdminSpreadFeeE6` and `newAdminNotionalFeeE8 > maxAdminNotionalFeeE8` before updating fees. [2](#0-1) 

`setPoolBinAdditionalFees` has no equivalent check: [1](#0-0) 

`setBinAdditionalFees` on the pool also has no cap: [8](#0-7) 

During a swap, the bin's `addFeeBuyE6`/`addFeeSellE6` are read from storage and added to `baseFeeX64` with no ceiling before being passed to `SwapMath`: [9](#0-8) 

The quote functions (`getSellAndBuyPrices`, `MetricOmmPoolDataProvider`) also read these values from storage, so a quote obtained before the admin's front-run will not reflect the elevated fee. [7](#0-6) 

### Impact Explanation
A trader obtains a quote, the pool admin front-runs with `setPoolBinAdditionalFees(pool, activeBin, 65535, 65535)`, the trader's swap executes at up to ~6.55% additional fee above the quoted rate, and the trader receives materially less output than expected. The admin can reset the fee after the swap. This is direct loss of swap output token balance for the trader, caused by an admin-boundary break (no cap on bin additional fees despite the system having explicit fee caps for other admin paths).

### Likelihood Explanation
Any pool admin (a semi-trusted role, not the factory owner) can execute this on any pool they administer. It requires no special conditions beyond the admin being willing to act maliciously and the pool being active. On chains with a public mempool, the front-run is straightforward.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. Introduce a `maxAdminBinFeeE6` storage variable (settable by the factory owner within a hard ceiling) and enforce `addFeeBuyE6 <= maxAdminBinFeeE6` and `addFeeSellE6 <= maxAdminBinFeeE6` before calling `setBinAdditionalFees`.

### Proof of Concept
```
1. Pool is active; active bin is bin 0.
2. Trader calls getSellAndBuyPrices() → receives quote Q (output for given input).
3. Admin calls factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535) — no revert.
4. Trader's swap transaction lands; swap math uses addFeeBuyE6=65535 → trader receives output < Q.
5. Admin calls factory.setPoolBinAdditionalFees(pool, 0, 0, 0) to reset.
Assert: actual output < Q (quoted output).
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L414-415)
```text
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L450-457)
```text
  function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L464-474)
```text
  function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    onlyFactory
    nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
  {
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L994-1004)
```text
          (curPosInBinCache, outToken0AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken0InBinSpecifiedIn(
              binState,
              curPosInBinCache,
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
            );
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/utils/MetricReentrancyGuardTransient.sol (L29-33)
```text
  function _nonReentrantBeforeView() private view {
    if (_currentAction() != 0) {
      revert ReentrancyGuardReentrantCall();
    }
  }
```
