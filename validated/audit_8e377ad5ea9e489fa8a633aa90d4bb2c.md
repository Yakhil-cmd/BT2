### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFees` correctly enforces `maxAdminSpreadFeeE6` on the global admin spread fee, but `setPoolBinAdditionalFees` forwards per-bin additional fees directly to the pool with **no cap check**. A pool admin can set `addFeeBuyE6` / `addFeeSellE6` to `type(uint16).max` (65 535 in E6 = 6.5535%) on every active bin, charging traders a total effective fee far above the factory-enforced ceiling and undermining the factory owner's fee-governance invariant.

---

### Finding Description

`setPoolAdminFees` guards the global admin component:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

`setPoolBinAdditionalFees`, callable by the same pool admin, has **no analogous guard**:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` only validates the bin index, not the fee magnitude:

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
```

During every swap, the per-bin additional fee is added directly to `baseFeeX64` before the fee multiplication:

```solidity
// MetricOmmPool.sol L910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

`HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) is the absolute ceiling for the global spread fee. `addFeeBuyE6` is `uint16`, so its maximum is 65 535 ≈ 6.55% — a value that can be set **independently** of and **in addition to** the global spread fee, with no factory-level cap.

---

### Impact Explanation

The factory owner may lower `maxAdminSpreadFeeE6` to, e.g., 1 000 (0.1%) to protect users. The pool admin complies with `setPoolAdminFees` but then calls `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` on every bin. Traders in those bins pay an additional ~6.55% per bin on top of the oracle spread and the global fee, far exceeding the cap the factory owner intended to enforce. The admin's proportional share of the inflated fee (via `spreadFeeE6`) also increases, giving the admin a financial incentive. The factory owner's fee-governance invariant — that no pool admin can charge above `maxAdminSpreadFeeE6` — is broken.

---

### Likelihood Explanation

The pool admin is semi-trusted and can call `setPoolBinAdditionalFees` at any time with no timelock. No off-chain monitoring or on-chain guard prevents it. The call is a single transaction with no preconditions beyond holding the pool admin role.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. The per-bin additional fees should be bounded by `maxAdminSpreadFeeE6` (or a dedicated per-bin cap):

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

---

### Proof of Concept

1. Factory owner sets `maxAdminSpreadFeeE6 = 1_000` (0.1%) via `setFeeCaps`.
2. Pool admin calls `setPoolAdminFees(pool, 1_000, 0)` — passes the cap check.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — no cap check, succeeds.
4. A trader swaps through bin 0. The effective buy fee is `baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)` ≈ oracle spread + 6.55%, far above the 0.1% cap the factory owner enforced.
5. The pool admin receives a proportional share of the inflated fee via `spreadFeeE6`.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
