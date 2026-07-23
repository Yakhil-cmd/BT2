### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via `setPoolBinAdditionalFees()` — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolAdminFees()` enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps before updating pool fees, but the sibling function `setPoolBinAdditionalFees()` forwards per-bin additional fees directly to the pool with no cap check at all. A pool admin can therefore set per-bin `addFeeBuyE6` / `addFeeSellE6` values that, when added to the base spread fee, push the effective swap fee above the factory-enforced maximum.

### Finding Description

`setPoolAdminFees()` explicitly validates both fee components against factory caps before applying them:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees()`, which is also callable by the pool admin, performs no such validation and passes the caller-supplied `uint16` values straight through to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees()` likewise applies no cap — it only validates the bin index:

```solidity
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

The `addFeeBuyE6` / `addFeeSellE6` fields are stored in `BinState` and are additive to the pool's base `spreadFeeE6` during swap execution. The `uint16` type allows values up to 65 535 (≈ 6.55 % in E6 units). The hard cap for admin spread fees is `HARD_MAX_SPREAD_FEE_E6 = 200 000` (20 %). [4](#0-3) 

If the base `spreadFeeE6` is already at the maximum (200 000), a pool admin can additionally set `addFeeBuyE6 = 65535` on the active bin, making the effective per-bin fee 265 535 (≈ 26.55 %) — 33 % above the documented cap.

### Impact Explanation

Traders swapping through a bin whose `addFeeBuyE6` / `addFeeSellE6` has been set above the residual cap headroom pay more than the factory-enforced maximum spread fee. The excess is extracted from the trader's input and credited to the pool's surplus, from which it flows to the protocol/admin on the next `collectFees` call. This is a direct, quantifiable loss of trader principal above the documented fee ceiling and constitutes an admin-boundary break: the pool admin exceeds the cap the factory is supposed to enforce.

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly expected to be constrained by `maxAdminSpreadFeeE6`. The function `setPoolBinAdditionalFees()` is a normal, documented pool-admin action. No special conditions, malicious tokens, or privileged factory-owner cooperation are required — the pool admin calls it directly. The inconsistency is structural and reachable on every deployed pool with a mutable admin.

### Recommendation

Add the same cap guard to `setPoolBinAdditionalFees()` in the factory. Because bin additional fees are additive to the base spread, the correct bound is the remaining headroom under `maxAdminSpreadFeeE6` minus the pool's current `adminSpreadFeeE6`, or at minimum a hard check that each value does not exceed `maxAdminSpreadFeeE6` individually:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

A stricter bound would also account for the existing `adminSpreadFeeE6` already applied to the pool, ensuring the combined effective fee never exceeds `maxAdminSpreadFeeE6`.

### Proof of Concept

1. Factory is deployed with `maxAdminSpreadFeeE6 = 200_000` (20 %).
2. Pool admin creates a pool with `adminSpreadFeeE6 = 200_000` (already at the cap).
3. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
4. No revert occurs — the factory forwards the call without any cap check.
5. The active bin (index 0) now has `addFeeBuyE6 = 65535` and `addFeeSellE6 = 65535`.
6. A trader swapping through bin 0 pays an effective spread fee of `200_000 + 65_535 = 265_535` (≈ 26.55 %), which is 33 % above the documented 20 % maximum.
7. The excess fee accrues as pool surplus and is collected by the admin on the next `collectPoolFees()` call. [5](#0-4) [2](#0-1) [6](#0-5)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
  }
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
