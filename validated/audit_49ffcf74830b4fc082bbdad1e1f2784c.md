### Title
Pool Admin Bypasses Fee Cap via `setPoolBinAdditionalFees` Missing Cap Validation — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8` caps before updating fees, but `setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with **no cap check**. After the factory owner lowers `maxAdminSpreadFeeE6` via `setFeeCaps`, the pool admin can still push per-bin fees up to `type(uint16).max` (65 535 E6 ≈ 6.55%), exceeding the newly-lowered cap and overcharging traders.

### Finding Description

`setPoolAdminFees` guards both fee components:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, also callable by the pool admin, has **no such guard**:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`setFeeCaps` can lower `maxAdminSpreadFeeE6` to any value down to 0, and auto-clamps the factory default, but it does **not** retroactively clamp existing per-bin fees or block future `setPoolBinAdditionalFees` calls: [3](#0-2) 

The `createPool` path validates the admin spread fee component at deploy time: [4](#0-3) 

But the bin-level path is never validated against any cap, either at creation or post-deployment.

### Impact Explanation

Per-bin additional fees are applied on top of the global spread fee during swap execution. A pool admin who sets `addFeeBuyE6 = 65535` on an active bin charges traders ≈6.55% extra per swap in that bin — potentially far above the cap the factory owner intended to enforce. Traders suffer direct, measurable loss of swap output with no on-chain recourse.

### Likelihood Explanation

The factory owner must first lower `maxAdminSpreadFeeE6` below 65 535 (the `uint16` ceiling) for the gap to be exploitable. `setFeeCaps` is a routine governance action (e.g., tightening fees across the protocol). Once the cap is lowered, any pool admin — a semi-trusted role — can immediately call `setPoolBinAdditionalFees` with the maximum `uint16` value, bypassing the new cap without any timelock or additional privilege.

### Recommendation

Add the same cap guard to `setPoolBinAdditionalFees` that exists in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

### Proof of Concept

1. Factory owner calls `setFeeCaps(200_000, 1_000, 1_000_000, 1_000_000)` — lowering `maxAdminSpreadFeeE6` to 1 000 (0.1%).
2. Pool admin calls `setPoolAdminFees(pool, 1_001, 0)` → reverts `AdminFeeTooHigh`. Cap is enforced here.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` → **succeeds**. No cap check.
4. Every swap touching bin 0 now pays ≈6.55% additional fee, 65× the intended cap, with the excess going to the admin fee destination. [1](#0-0) [2](#0-1)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-315)
```text
  function setFeeCaps(
    uint24 newMaxProtocolSpreadFeeE6,
    uint24 newMaxAdminSpreadFeeE6,
    uint24 newMaxProtocolNotionalFeeE8,
    uint24 newMaxAdminNotionalFeeE8
  ) external override onlyOwner {
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
    }
    maxProtocolSpreadFeeE6 = newMaxProtocolSpreadFeeE6;
    maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
    maxProtocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
    maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;

    if (spreadProtocolFeeE6 > newMaxProtocolSpreadFeeE6) {
      uint24 oldFeeE6 = spreadProtocolFeeE6;
      spreadProtocolFeeE6 = newMaxProtocolSpreadFeeE6;
      emit SpreadProtocolFeeDefaultUpdated(oldFeeE6, newMaxProtocolSpreadFeeE6);
    }
    if (protocolNotionalFeeE8 > newMaxProtocolNotionalFeeE8) {
      uint24 oldFeeE8 = protocolNotionalFeeE8;
      protocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
      emit ProtocolNotionalFeeDefaultUpdated(oldFeeE8, newMaxProtocolNotionalFeeE8);
    }

    emit FeeCapsUpdated(
      newMaxProtocolSpreadFeeE6, newMaxAdminSpreadFeeE6, newMaxProtocolNotionalFeeE8, newMaxAdminNotionalFeeE8
    );
  }
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L449-457)
```text
  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L548-563)
```text
  function _validatePoolParameters(PoolParameters calldata params) internal view {
    if (params.token0 == address(0) || params.token1 == address(0) || params.token0 == params.token1) {
      revert InvalidTokenConfig();
    }
    if (params.admin == address(0)) revert InvalidAdmin();
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    if (spreadProtocolFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (protocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    if (params.initialAmount0PerShareE18 == 0 || params.initialAmount1PerShareE18 == 0) {
      revert InvalidInitialAmount();
    }
    if (params.minimalMintableLiquidity == 0) revert InvalidMinimalMintableLiquidity();
  }
```
