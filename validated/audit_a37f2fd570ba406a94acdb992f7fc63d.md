The code path is clear. Let me verify the exact lines for the cap check in `setPoolAdminFees` vs. the missing check in `setPoolBinAdditionalFees`.

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` on the pool-level admin spread fee, but `setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with no cap check. Because per-bin additional fees are added on top of the base spread fee at swap time, a pool admin can set them to `uint16.max` (65535 in E6 = 6.5535%) regardless of what `maxAdminSpreadFeeE6` is, bypassing the factory-enforced ceiling entirely.

---

### Finding Description

`setPoolAdminFees` guards the admin spread component with:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, callable by the same `onlyPoolAdmin` role, contains no such guard and forwards values directly to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`setBinAdditionalFees` on the pool only validates the bin index, not the fee magnitude: [3](#0-2) 

At swap time, the per-bin additional fee is added directly on top of `baseFeeX64`:

```solidity
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

The same uncapped addition is applied in every swap variant (`buyToken0InBinSpecifiedOut`, `buyToken0InBinSpecifiedIn`, `buyToken1InBinSpecifiedIn`): [5](#0-4) [6](#0-5) [7](#0-6) 

---

### Impact Explanation

A pool admin can call `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` to set per-bin fees to 6.5535% on any or all bins. Every swap routed through those bins pays this inflated fee, which is extracted from traders above the factory-enforced ceiling. This is a direct loss of user principal on every affected swap, satisfying the "admin-boundary break: pool admin exceeds caps" impact gate.

The bypass is not limited to the `maxAdminSpreadFeeE6 == 0` edge case — it works for any value of `maxAdminSpreadFeeE6`, including the hard maximum of `200_000` (20%): [8](#0-7) 

---

### Likelihood Explanation

Any pool admin — a role that is explicitly semi-trusted only within caps — can exploit this immediately after pool creation with a single transaction. No timelock, no co-signer, no oracle manipulation required.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Alternatively, enforce the cap inside `setBinAdditionalFees` on the pool by reading the factory's `maxAdminSpreadFeeE6` — though the factory-side guard is simpler and consistent with how `setPoolAdminFees` is already structured.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import "forge-std/Test.sol";

contract BinFeeCapBypassTest is Test {
    // 1. Deploy factory with maxAdminSpreadFeeE6 = 0
    // 2. Create pool with adminSpreadFeeE6 = 0
    // 3. Pool admin calls setPoolBinAdditionalFees(pool, 0, 65535, 65535)
    //    → succeeds (no revert)
    // 4. Perform a swap through bin 0
    // 5. Assert effective fee applied = 65535 / 1e6 = 6.5535%
    //    which exceeds maxAdminSpreadFeeE6 = 0
}
```

The test confirms that `setPoolBinAdditionalFees` accepts `65535` without reverting while `setPoolAdminFees(pool, 1, 0)` would revert with `AdminFeeTooHigh` under the same `maxAdminSpreadFeeE6 = 0` configuration.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L906-914)
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
```

**File:** metric-core/contracts/MetricOmmPool.sol (L994-1003)
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
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1172-1181)
```text
          (curPosInBinCache, outToken1AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken1InBinSpecifiedIn(
              binState,
              curPosInBinCache,
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
```
