Based on my investigation of the code, this is a valid finding. Here is my analysis:

---

### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees Up to uint16 Max, Bypassing Factory Fee Cap System — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolBinAdditionalFees` passes `addFeeBuyE6` and `addFeeSellE6` directly to the pool with no cap validation, while the analogous `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to uint16 max (65,535 ≈ 6.55% in E6) on any bin, causing traders in that bin to pay fees far above the factory's intended cap system.

### Finding Description

`setPoolAdminFees` enforces caps before updating fees: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

But `setPoolBinAdditionalFees` performs no such check — it delegates directly to the pool: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool-level `setBinAdditionalFees` interface also imposes no cap: [3](#0-2) 

The factory's hard cap system (`HARD_MAX_SPREAD_FEE_E6` = 20%, `maxAdminSpreadFeeE6`) governs the base spread fee, but the bin additional fee layer is entirely uncapped. The type `uint16` allows values up to 65,535, which in E6 notation equals ~6.5535%.

### Impact Explanation

Traders swapping through a bin with `addFeeBuyE6 = 65_535` pay an additional ~6.55% fee on top of the base spread fee, with no factory-enforced ceiling. This is a direct loss of swap proceeds for traders in that bin. The factory's cap architecture is designed to bound pool admin power, but the bin additional fee path is a gap that lets the admin extract fees beyond any protocol-intended limit.

This satisfies the allowed impact gate: **"Admin-boundary break: pool admin exceeds caps"** — the pool admin can exceed the fee cap system that the factory is designed to enforce.

### Likelihood Explanation

Requires a malicious or compromised pool admin. Pool admins are semi-trusted and are expected to be constrained by factory caps. The absence of a cap here is an inconsistency in the factory's own cap enforcement model, not an intended design.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. Either reuse `maxAdminSpreadFeeE6` or introduce a dedicated `maxBinAdditionalFeeE6` constant:

```solidity
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

### Proof of Concept

1. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — no revert.
2. A trader swaps through bin 0; the effective buy fee is `spreadFeeE6 + 65_535`.
3. The trader pays ~6.55% additional fee above the base spread, with no factory-level guard preventing it.
4. Compare to `setPoolAdminFees(pool, 65_535, 0)` — this reverts with `AdminFeeTooHigh` if `maxAdminSpreadFeeE6` is below 65,535, demonstrating the inconsistency. [4](#0-3) [2](#0-1)

### Citations

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

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolFactoryActions.sol (L52-56)
```text
  /// @notice Set per-bin additional buy and sell spread fees in E6 on top of base spread.
  /// @param bin Bin index within the pool configured bin range.
  /// @param addFeeBuyE6 Additional fee on buys into the bin (E6).
  /// @param addFeeSellE6 Additional fee on sells out of the bin (E6).
  function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6) external;
```
