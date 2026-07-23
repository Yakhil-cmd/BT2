### Title
Pool Admin Can Set Per-Bin Additional Fees Without Any Factory Cap, Bypassing the Fee Cap System - (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

The factory enforces explicit caps (`maxAdminSpreadFeeE6`, `maxAdminNotionalFeeE8`) on the pool admin's base spread and notional fees, but the `setPoolBinAdditionalFees` path applies **no cap whatsoever** on `addFeeBuyE6` / `addFeeSellE6`. A pool admin can set per-bin additional fees to any value up to `uint16.max` (65 535 in E6 ≈ 6.55 %) on any bin, silently exceeding the intended fee-cap boundary and causing traders to overpay on every swap routed through that bin.

---

### Finding Description

The factory's fee-cap system is built around four guarded values:

```
HARD_MAX_SPREAD_FEE_E6  = 200_000   // 20 %
HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000 // 1 %
``` [1](#0-0) 

These are enforced in `setPoolAdminFees`:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [2](#0-1) 

However, the parallel pool-admin entrypoint `setPoolBinAdditionalFees` passes the caller-supplied values straight through to the pool with **no cap check**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

The pool's `setBinAdditionalFees` only validates the bin index, not the fee magnitudes:

```solidity
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [4](#0-3) 

During every swap the bin additional fee is added directly on top of the oracle-derived base fee before computing the gross input required from the trader:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [5](#0-4) 

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6)
``` [6](#0-5) 

With `addFeeBuyE6 = 65535` (the `uint16` maximum), the additional fee is `65535 / 1e6 ≈ 6.55 %` per bin, on top of whatever base spread fee is already active. The pool admin can apply this to every bin simultaneously, stacking uncapped additional fees across the entire price range.

---

### Impact Explanation

Every swap routed through a bin whose `addFeeBuyE6` or `addFeeSellE6` has been set to the maximum pays up to 6.55 % more than the fee-cap system is supposed to allow. Because the additional fee is charged as part of the gross input calculation, the excess is taken directly from the trader's input token balance — a direct loss of user principal on every affected swap. The pool admin can apply this to all bins simultaneously, making the pool effectively unusable at fair prices while still appearing active.

---

### Likelihood Explanation

The pool admin is explicitly described as "semi-trusted only inside caps." The fee-cap system (`maxAdminSpreadFeeE6`, `maxAdminNotionalFeeE8`) exists precisely to bound the pool admin's ability to extract value from traders. The bin additional fee path is the only admin fee-setting function that bypasses this system entirely. Any pool admin — including one who has legitimately acquired the role — can exploit this gap immediately, with no timelock and no protocol override.

---

### Recommendation

Add a factory-level cap check in `setPoolBinAdditionalFees` analogous to the check in `setPoolAdminFees`. Introduce a `maxAdminBinAdditionalFeeE6` state variable (or reuse `maxAdminSpreadFeeE6`) and revert if either `addFeeBuyE6` or `addFeeSellE6` exceeds it:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The new cap should be governed by the same `setFeeCaps` / hard-limit machinery as the existing spread and notional caps.

---

### Proof of Concept

1. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
2. No revert — the factory passes the values directly to the pool.
3. A trader calls `swap(...)` routing through bin 0.
4. The pool computes the effective buy fee as `baseFeeX64 + Math.mulDiv(65535, ONE_X64, 1e6)`, adding ≈ 6.55 % on top of the oracle-derived spread.
5. The trader's gross input is inflated by 6.55 % beyond what the fee-cap system permits, with the excess accruing to LPs rather than being bounded by any protocol guard.
6. The pool admin can repeat for every bin in the pool's range, making the cumulative overcharge apply to all swaps. [3](#0-2) [7](#0-6)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
