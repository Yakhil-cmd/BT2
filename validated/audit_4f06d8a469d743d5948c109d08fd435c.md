### Title
Pool Admin Bypasses Factory Fee Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` to the pool with **no cap validation**, while the parallel path `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to `type(uint16).max` (65 535 E6 ≈ 6.55 %) on any or all bins, charging traders a total effective fee that exceeds the factory's hard cap without any factory-level guard.

### Finding Description

`setPoolAdminFees` enforces the factory cap:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has **no equivalent check**:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index:

```solidity
// MetricOmmPool.sol:464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [3](#0-2) 

In every swap path the bin additional fee is added directly on top of the oracle-derived base fee before being applied to the trader's input:

```solidity
// MetricOmmPool.sol:999 (buyToken0InBinSpecifiedIn path)
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The same pattern appears in all four swap directions (lines 910, 999, 1088, 1177). [5](#0-4) 

The `spreadFeeE6` stored on the pool (capped at `HARD_MAX_SPREAD_FEE_E6` = 200 000 E6 = 20 %) is used only to split the LP fee between protocol and LP — it does **not** bound the total fee charged to the trader. The total fee charged is `baseFeeX64 + addFeeX64`, where `addFeeX64` is uncapped. [6](#0-5) 

### Impact Explanation

A pool admin can set `addFeeBuyE6 = addFeeSellE6 = type(uint16).max` (65 535 E6 ≈ 6.55 %) on every bin. Every swap through those bins pays an additional ~6.55 % on top of the oracle spread, regardless of the factory's hard cap. For a $1 M trade this is ~$65 500 extracted from the trader beyond the capped amount. The surplus accrues as LP-side spread surplus and is split between protocol and admin at collection time — the pool admin's own fee destination receives a share. This is a direct loss of trader principal caused by a semi-trusted role operating outside the factory's cap boundary.

### Likelihood Explanation

The pool admin is a single address set at pool creation. Any pool whose admin is compromised, colluding, or simply acting in bad faith can immediately call `setPoolBinAdditionalFees` with `type(uint16).max` on all bins. No timelock, no multisig requirement, and no factory-level guard prevents this. The call is a single transaction.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the check in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxBinAdditionalFeeE6` cap that the factory owner can configure, and enforce it here and in `_unpackAndValidateBinStates` at pool creation time.

### Proof of Concept

1. Factory owner deploys a pool with `maxAdminSpreadFeeE6 = 200 000` (20 %).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — no revert.
3. A trader calls `pool.swap(...)` routing through bin 0.
4. Inside `_swapToken1ForToken0SpecifiedInput`, the effective buy fee is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — approximately oracle spread + 6.55 %.
5. The trader pays ~6.55 % more than the oracle spread alone, exceeding the factory's 20 % hard cap when combined with a non-zero base spread, with no on-chain guard having prevented the admin from setting this value. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L61-68)
```text
  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxAdminSpreadFeeE6;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxProtocolNotionalFeeE8;

  /// @inheritdoc IMetricOmmPoolFactory
  uint24 public override maxAdminNotionalFeeE8;
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
