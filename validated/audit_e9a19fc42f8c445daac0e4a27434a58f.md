The code confirms this is a real vulnerability. Let me lay out the exact findings:

**Key facts from the code:**

1. `setPoolAdminFees` in `MetricOmmPoolFactory.sol` has a cap check: [1](#0-0) 

2. `setPoolBinAdditionalFees` passes through with **zero validation** on the fee values: [2](#0-1) 

3. `setBinAdditionalFees` on the pool only validates bin index range, not fee magnitude: [3](#0-2) 

4. In swap execution, the effective buy fee is `baseFeeX64 + mulDiv(addFeeBuyE6, ONE_X64, 1e6)` — purely additive, no combined ceiling: [4](#0-3) 

5. The hard cap for admin spread fees is `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%), but `addFeeBuyE6` is `uint16` with max 65,535 (6.5535%) and is completely uncapped: [5](#0-4) 

---

### Title
Pool Admin Bypasses Fee Cap via Uncapped Per-Bin `addFeeBuyE6` in `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`setPoolBinAdditionalFees` applies no upper-bound validation on `addFeeBuyE6` / `addFeeSellE6`, while the parallel `setPoolAdminFees` path enforces `maxAdminSpreadFeeE6`. A pool admin can set `addFeeBuyE6 = type(uint16).max` (65,535 = 6.5535%) on any bin, and this value is added directly on top of `baseFeeX64` (derived from the global `spreadFeeE6`) in every swap through that bin, with no combined ceiling check anywhere in the execution path.

### Finding Description
The factory's fee governance model establishes `maxAdminSpreadFeeE6` (bounded by `HARD_MAX_SPREAD_FEE_E6 = 200_000`) as the ceiling for pool-admin-controlled spread fees. `setPoolAdminFees` enforces this cap. However, `setPoolBinAdditionalFees` — also a pool-admin action — forwards `addFeeBuyE6` and `addFeeSellE6` directly to `MetricOmmPool.setBinAdditionalFees` without any magnitude check.

During swap execution, the per-bin effective fee is computed as:

```
currBinBuyFeeX64 = params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

`params.baseFeeX64` is derived from the oracle bid/ask spread plus the global `spreadFeeE6`. The `addFeeBuyE6` component is purely additive with no cap on the sum. Setting `addFeeBuyE6 = 65535` adds 6.5535% on top of whatever the global spread fee is, with no check that the total remains within any disclosed limit.

### Impact Explanation
Traders buying token0 through the affected bin pay fees exceeding any configured or disclosed cap. The excess fee is extracted from their token1 input — direct loss of principal above Sherlock thresholds. The pool admin can target specific bins (e.g., the active bin) to maximize impact on all swaps in that direction.

### Likelihood Explanation
The pool admin is a semi-trusted role expected to operate within caps. The absence of a cap check on `setPoolBinAdditionalFees` is a straightforward omission that any pool admin can exploit immediately, with no timelock, no additional privilege, and no special precondition beyond having the pool admin role.

### Recommendation
Add a combined cap check in `setPoolBinAdditionalFees` (or in `setBinAdditionalFees` on the pool) that ensures `addFeeBuyE6` and `addFeeSellE6` do not exceed `maxAdminSpreadFeeE6` (converted to E6 units), or alternatively enforce that `spreadFeeE6 + addFeeBuyE6 ≤ HARD_MAX_SPREAD_FEE_E6` at the time of the call.

### Proof of Concept
1. Deploy a pool with `maxAdminSpreadFeeE6 = 200_000` (20%) and `spreadFeeE6 = 200_000`.
2. As pool admin, call `factory.setPoolBinAdditionalFees(pool, 0, type(uint16).max, 0)` — sets `addFeeBuyE6 = 65535` on bin 0. No revert.
3. Execute a token1→token0 swap through bin 0.
4. Observe effective buy fee = `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` ≈ global spread + 6.5535%, exceeding the 20% cap by the uncapped bin fee on top of an already-maxed global spread, and exceeding any reasonable disclosed ceiling in lower-spread configurations.
5. Assert that the token1 input charged to the trader exceeds what would be charged at the capped fee rate.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-1003)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
```
