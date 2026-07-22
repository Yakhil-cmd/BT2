Now I have enough information to render a verdict. Let me trace the full path:

### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees, Bypassing the Global Spread Fee Cap — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` applies no upper-bound validation on `addFeeBuyE6` / `addFeeSellE6`, while the parallel global-spread-fee path (`setPoolAdminFees`) is strictly capped. A pool admin can set per-bin fees to `type(uint16).max` (65 535 E6 = 6.5535 %) on any bin, bypassing the hard cap of `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %) that governs the global spread fee. The extra spread is never credited to LP bins; it accumulates as pool-balance surplus and is fully distributed to protocol and admin on the next `collectFees` call, at the expense of LP swap revenue.

---

### Finding Description

**Entry point — no cap check:**

`MetricOmmPoolFactory.setPoolBinAdditionalFees` (pool-admin-only) forwards the caller-supplied values directly to the pool with zero validation:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [1](#0-0) 

The pool-level handler only validates the bin index, not the fee magnitude:

```solidity
// MetricOmmPool.sol L464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [2](#0-1) 

**Contrast with the capped global-fee path:**

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6`, which itself is bounded by `HARD_MAX_SPREAD_FEE_E6 = 200_000`: [3](#0-2) [4](#0-3) 

No equivalent guard exists for per-bin fees.

**How the extra fee becomes surplus (not LP revenue):**

During a swap, the bin additional fee is added to `baseFeeX64` to widen the effective spread:

```solidity
// MetricOmmPool.sol L999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [5](#0-4) 

The spread fee (`protocolFeeScaled`) is explicitly **not** credited to LP bins:

```solidity
// MetricOmmPool.sol L729-736
// protocol fee is charged on the input token and does NOT enter bins.
binTotals.scaledToken0 =
    (uint256(binTotals.scaledToken0) + uint256(amount0DeltaScaled) - protocolFeeScaled).toUint128();
``` [6](#0-5) 

**`collectFees` distributes the inflated surplus to protocol and admin:**

```solidity
// MetricOmmPool.sol L385-395
uint256 surplus0Scaled =
    balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
...
uint256 spreadFee0ToAdminScaled = (surplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
uint256 spreadFee0ToProtocolScaled = (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
``` [7](#0-6) 

The surplus is the entire pool balance minus LP-owed bins minus notional fees. Inflating the spread via uncapped per-bin fees directly inflates this surplus, which is then fully paid out to protocol and admin.

---

### Impact Explanation

- **Admin-boundary break**: The pool admin can set per-bin fees to 65 535 E6 (6.5535 %) with no cap, while the global spread fee is hard-capped at 200 000 E6 (20 %). The total effective spread on a bin = global spread fee + bin additional fee, which can exceed the hard cap.
- **LP revenue loss**: Every swap through the affected bin generates less LP bin-balance growth (the extra spread goes to surplus, not bins). LPs earn less per swap than the fee cap system was designed to allow.
- **Bad-price execution for traders**: Traders receive worse prices than the capped fee schedule implies.
- **Protocol/admin over-collection**: `collectFees` distributes the inflated surplus to protocol and admin, receiving more than the capped fee rates would permit.

---

### Likelihood Explanation

The pool admin role is semi-trusted and explicitly in scope per the audit's admin-boundary pivot. The call requires only `poolAdmin[pool] == msg.sender`, which is a normal operational role. No timelock, no factory-owner approval, and no cap check stands between the pool admin and setting `addFeeBuyE6 = 65535`.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (or in `setBinAdditionalFees` on the pool) analogous to the check in `setPoolAdminFees`:

```solidity
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Alternatively, enforce that `spreadFeeE6 + addFeeBuyE6 ≤ HARD_MAX_SPREAD_FEE_E6` and `spreadFeeE6 + addFeeSellE6 ≤ HARD_MAX_SPREAD_FEE_E6` so the total effective spread per bin cannot exceed the hard cap.

---

### Proof of Concept

1. Deploy pool with `spreadFeeE6 = 0` (or any value), `maxAdminSpreadFeeE6 = 10_000`.
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — succeeds with no revert.
3. LP adds liquidity to bin 0.
4. Trader swaps through bin 0; effective spread = `baseFeeX64 + 65535/1e6 * ONE_X64`.
5. Assert `binTotals.scaledToken0` grew by less than `amountIn - baseFee * amountIn` (the extra 6.5535 % went to surplus).
6. Call `factory.collectPoolFees(pool)`; assert protocol + admin received the inflated surplus, exceeding what `maxAdminSpreadFeeE6 = 10_000` would have permitted under the global fee path.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-395)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;

    unchecked {
      uint256 spreadFee0ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * adminSpreadFeeE6_) / spreadSumE6;

      uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * protocolSpreadFeeE6_) / spreadSumE6;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L729-736)
```text
      // Update bin totals: protocol fee is charged on the input token and does NOT enter bins.
      // For zeroForOne: token0 enters bins (minus protocolFeeScaled), token1 leaves bins.
      // For !zeroForOne: token1 enters bins (minus protocolFeeScaled), token0 leaves bins.
      if (zeroForOne) {
        // casting to uint256 is safe because amount0DeltaScaled is positive in zeroForOne flow.
        // forge-lint: disable-next-line(unsafe-typecast)
        binTotals.scaledToken0 =
          (uint256(binTotals.scaledToken0) + uint256(amount0DeltaScaled) - protocolFeeScaled).toUint128(); // forge-lint: disable-line(unsafe-typecast)
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
