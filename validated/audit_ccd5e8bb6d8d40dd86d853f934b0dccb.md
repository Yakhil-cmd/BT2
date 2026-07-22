### Title
Pool Admin Bypasses Fee Cap System via Uncapped `setPoolBinAdditionalFees` — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` directly to the pool with **no cap validation**, while the parallel global-fee setter `setPoolAdminFees` explicitly enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8`. A pool admin can set per-bin additional fees to `type(uint16).max` (65,535 in E6 units ≈ 6.55%) on any bin, adding effective swap cost on top of the already-capped global spread fee and breaking the admin-boundary invariant the factory is designed to enforce.

---

### Finding Description

The factory's fee-cap system is built around two hard limits:

```
HARD_MAX_SPREAD_FEE_E6  = 200_000  (20%)
HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000 (1%)
``` [1](#0-0) 

The global admin-fee setter enforces these caps:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [2](#0-1) 

The per-bin setter has **no such check**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index:

```solidity
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [4](#0-3) 

During every swap, the bin additional fee is added directly on top of the base fee derived from the global spread:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [5](#0-4) 

The `BinState` struct stores `addFeeBuyE6` / `addFeeSellE6` as `uint16`, so the maximum settable value is **65,535** (≈ 6.55% in E6 units): [6](#0-5) 

---

### Impact Explanation

The total effective fee charged to a trader on a given bin is:

```
effective_fee = global_spreadFeeE6 + addFeeBuyE6 (or addFeeSellE6)
```

The global spread fee is already capped at up to 40% (20% protocol + 20% admin). Adding `type(uint16).max` bin additional fees (≈ 6.55%) on top pushes the per-bin effective fee to ≈ 46.55%, far beyond the hard cap the factory is supposed to enforce. Traders swapping through affected bins pay excess fees that the protocol's cap system was designed to prevent. This is a direct loss of trader principal and an admin-boundary break: the pool admin exceeds the documented fee caps through a path the factory does not guard.

---

### Likelihood Explanation

The pool admin is semi-trusted and has direct, unrestricted access to `setPoolBinAdditionalFees` at any time after pool creation. No timelock, no protocol co-signature, and no cap check stands between the admin and setting `addFeeBuyE6 = type(uint16).max` on every bin. A malicious or compromised pool admin can execute this in a single transaction.

---

### Recommendation

Add a cap check in `MetricOmmPoolFactory.setPoolBinAdditionalFees` mirroring the guard in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
+   if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
+   if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxBinAdditionalFeeE6` cap that the factory owner can configure, keeping bin-level and global-level fee governance consistent.

---

### Proof of Concept

1. Pool is created with `adminSpreadFeeE6 = maxAdminSpreadFeeE6` (e.g., 200,000 = 20%) and `spreadProtocolFeeE6 = 200,000` (20%). Total global spread = 40%.
2. Pool admin calls:
   ```solidity
   factory.setPoolBinAdditionalFees(pool, 0, type(uint16).max, type(uint16).max);
   // addFeeBuyE6 = addFeeSellE6 = 65_535 ≈ 6.55%
   ```
   No revert occurs — no cap check exists.
3. A trader calls `pool.swap(...)` routing through bin 0. The swap math computes:
   ```
   effectiveFeeX64 = baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)
   ```
   The trader pays ≈ 46.55% total fee on that bin's liquidity — 6.55% above the hard cap the factory is supposed to enforce.
4. The excess fee accrues to LPs (including the admin if they hold LP shares), extracting value from traders beyond the protocol's documented limits. [3](#0-2) [7](#0-6) [8](#0-7)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L908-915)
```text
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
