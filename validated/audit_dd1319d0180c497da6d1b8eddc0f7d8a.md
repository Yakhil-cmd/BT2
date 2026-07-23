The path is real. Here is the analysis:

**Key facts established:**

1. `setPoolBinAdditionalFees` in the factory passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with **zero cap check**: [1](#0-0) 

2. The analogous `setPoolAdminFees` **does** enforce caps: [2](#0-1) 

3. `setBinAdditionalFees` on the pool only validates bin range, not fee magnitude: [3](#0-2) 

4. The per-bin additional fee is applied directly in swap math, reducing trader output: [4](#0-3) 

5. The factory has `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` but **no equivalent cap** for per-bin additional fees. `uint16` max = 65535 → 6.5535% in E6 units: [5](#0-4) 

6. `BinState.addFeeBuyE6`/`addFeeSellE6` are `uint16` fields with no on-chain upper bound enforced anywhere in the call chain: [6](#0-5) 

**Verdict on the admin-boundary question:**

The contest scope explicitly treats the pool admin as **semi-trusted only inside caps and timelocks**, and the "Admin-boundary break" impact gate explicitly covers "pool admin exceeds caps." The asymmetry is clear: `setPoolAdminFees` is capped; `setPoolBinAdditionalFees` is not. This is a code-level validation gap, not a "trusted admin" assumption.

---

### Title
Pool Admin Can Set Per-Bin Additional Fees to Uncapped `uint16` Maximum, Bypassing the Factory Fee Cap System — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` to `MetricOmmPool.setBinAdditionalFees` with no factory-level cap, while the analogous `setPoolAdminFees` enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8`. A pool admin can set per-bin additional fees to the `uint16` maximum (65535 = 6.5535% in E6) on any bin, causing traders to pay up to 6.5535% additional fee per bin beyond the global spread cap.

### Finding Description
`MetricOmmPoolFactory.setPoolBinAdditionalFees` (line 450–457) is gated only by `onlyPoolAdmin` and passes the caller-supplied `addFeeBuyE6`/`addFeeSellE6` directly to `MetricOmmPool.setBinAdditionalFees` without any magnitude check. The pool-level function (line 464–474) validates only that the bin index is within `[LOWEST_BIN, HIGHEST_BIN]` and writes the values directly to `BinState` storage.

By contrast, `setPoolAdminFees` (line 414–415) explicitly reverts with `AdminFeeTooHigh` if `newAdminSpreadFeeE6 > maxAdminSpreadFeeE6` or `newAdminNotionalFeeE8 > maxAdminNotionalFeeE8`. No equivalent `maxAdminBinFeeE6` variable or check exists anywhere in the factory or pool.

The per-bin additional fee is applied in swap math as an additive term on top of `baseFeeX64` (line 1088), directly reducing the amount of output token a trader receives. Setting `addFeeSellE6 = 65535` on the active bin means every swap through that bin pays an extra 6.5535% fee, which is extracted from trader principal.

### Impact Explanation
Traders executing swaps through a bin with `addFeeBuyE6 = 65535` or `addFeeSellE6 = 65535` receive up to 6.5535% less output than the oracle/bin curve permits. This is a direct loss of trader principal above Sherlock thresholds, constituting both a bad-price execution (effective price deviates from the oracle-derived bin price by the uncapped fee) and an admin-boundary break (pool admin exceeds the cap system that governs all other fee parameters).

### Likelihood Explanation
The pool admin is a designated role assigned at pool creation. Any pool admin — whether compromised, acting in bad faith, or simply misconfigured — can call this function at any time with no timelock and no cap. The call requires no special pool state. Likelihood is medium given the pool admin is a semi-trusted role, but the missing guard makes exploitation trivially simple once the role is held.

### Recommendation
Add a factory-level cap for per-bin additional fees, mirroring the pattern used in `setPoolAdminFees`:

```solidity
// In MetricOmmPoolFactory state variables:
uint16 public maxAdminBinFeeE6;

// In setPoolBinAdditionalFees:
if (addFeeBuyE6 > maxAdminBinFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminBinFeeE6) revert AdminFeeTooHigh();
IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
```

The cap should be set and enforced by the factory owner via `setFeeCaps`, consistent with `maxAdminSpreadFeeE6`.

### Proof of Concept
```solidity
// createPool with any valid params
address pool = factory.createPool(params);

// Pool admin sets per-bin additional fee to uint16 max — no revert
vm.prank(admin);
factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

// Verify storage
(,,, uint16 buy, uint16 sell) = PoolStateLibrary._binState(pool, 0);
assertEq(buy, 65535);  // 6.5535% additional fee — no cap enforced
assertEq(sell, 65535);

// Any swap through bin 0 now pays 6.5535% extra, reducing output
// vs. a baseline swap with addFeeBuyE6 = 0
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L62-68)
```text
  uint24 public override maxAdminSpreadFeeE6;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxProtocolNotionalFeeE8;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxAdminNotionalFeeE8;
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L1084-1093)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken1InBinSpecifiedOut(
            binState,
            curPosInBinCache,
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
          );
```

**File:** metric-core/contracts/types/PoolStorage.sol (L19-25)
```text
struct BinState {
  uint104 token0BalanceScaled;
  uint104 token1BalanceScaled;
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
}
```
