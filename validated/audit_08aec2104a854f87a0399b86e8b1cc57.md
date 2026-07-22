### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards per-bin additional spread fees to the pool with **no cap check**, while the structurally identical `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees up to the `uint16` maximum (65 535 E6 = 6.5535%) on any bin, regardless of what the factory owner has configured as `maxAdminSpreadFeeE6` — including zero.

---

### Finding Description

The factory maintains a two-tier fee cap system. The factory owner sets `maxAdminSpreadFeeE6` via `setFeeCaps`, and `setPoolAdminFees` enforces it:

```solidity
// MetricOmmPoolFactory.sol lines 414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

However, `setPoolBinAdditionalFees` passes the values straight through with only an `onlyPoolAdmin` guard and no cap check:

```solidity
// MetricOmmPoolFactory.sol lines 450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` similarly only validates the bin index, not the fee magnitude:

```solidity
// MetricOmmPool.sol lines 464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6) external onlyFactory ... {
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

These per-bin fees are then added directly to the base oracle spread fee in every swap iteration:

```solidity
// MetricOmmPool.sol line 910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The same pattern applies to the sell direction and to exact-input swaps: [5](#0-4) 

The `BinState.addFeeBuyE6` and `addFeeSellE6` fields are `uint16`, so the unchecked maximum is `65 535 / 1e6 = 6.5535%` per bin. [6](#0-5) 

The hard cap `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) is enforced only on the global admin spread path; the factory owner can lower `maxAdminSpreadFeeE6` to any value including zero, but the bin-additional-fee path remains uncapped at 6.5535%. [7](#0-6) 

---

### Impact Explanation

Every swap through an affected bin pays `baseFee + addFeeBuyE6/1e6` (or sell equivalent) as the effective spread. The excess above the factory-enforced cap is charged to the trader and credited to LPs as LP fee. Traders receive worse execution than the protocol's fee cap is supposed to guarantee. If the factory owner has set `maxAdminSpreadFeeE6 = 0` to enforce a zero-admin-fee pool, the pool admin can still silently impose up to 6.5535% per-bin spread on every swap through that bin, draining value from traders to LPs without the factory owner's consent and in violation of the cap invariant.

This is an admin-boundary break: the pool admin exceeds the cap set by the factory owner via an uncapped path, causing bad-price execution for traders.

---

### Likelihood Explanation

The pool admin is a semi-trusted role with direct, permissionless access to `setPoolBinAdditionalFees`. No timelock, no additional approval, and no cap check stands between the admin and setting `addFeeBuyE6 = 65535` on the active bin. The trigger requires only a single transaction from the pool admin.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. The per-bin additional fees are additive spread, so they should be bounded by `maxAdminSpreadFeeE6`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the cap at the pool level inside `setBinAdditionalFees` by passing the current cap down from the factory, or store a per-pool bin-fee cap in factory storage.

---

### Proof of Concept

1. Factory owner calls `setFeeCaps(0, 0, ...)` to set `maxAdminSpreadFeeE6 = 0`, intending to prevent the pool admin from charging any admin spread.
2. Pool admin calls `setPoolAdminFees(pool, 1, 0)` → reverts with `AdminFeeTooHigh`. Cap is enforced.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` → **succeeds**. No cap check.
4. A trader swaps through bin 0. The effective buy fee is `baseFeeX64 + Math.mulDiv(65535, ONE_X64, 1e6)` — 6.5535% additional spread applied on top of the oracle spread, in direct violation of the `maxAdminSpreadFeeE6 = 0` cap.
5. The trader pays 6.5535% more than the oracle spread; the excess accrues to LPs, not to the admin directly, but the cap invariant is broken and the trader suffers the loss. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-415)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
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

**File:** metric-core/contracts/MetricOmmPool.sol (L906-915)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken0InBinSpecifiedOut(
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
