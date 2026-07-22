### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards per-bin additional fees directly to the pool with no cap validation, while every other admin fee setter enforces `maxAdminSpreadFeeE6`. A pool admin can set `addFeeBuyE6` / `addFeeSellE6` to `type(uint16).max` (65 535 E6 ≈ 6.55 %) on every bin, silently exceeding the protocol's admin fee cap and extracting more from traders than the cap permits.

### Finding Description

The factory enforces `maxAdminSpreadFeeE6` in `setPoolAdminFees`:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` performs no such check before forwarding to the pool:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` also has no cap check — it only validates the bin index: [3](#0-2) 

During every swap, `SwapMath` adds the per-bin fee on top of the base spread fee:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

Because `addFeeBuyE6` / `addFeeSellE6` are `uint16`, the maximum value is 65 535 E6 ≈ 6.55 %. Applied to every bin, this is additive on top of whatever `spreadFeeE6` is already set to, pushing the effective admin-controlled fee above `maxAdminSpreadFeeE6` (hard-capped at `HARD_MAX_SPREAD_FEE_E6 = 200 000` E6 = 20 %). [5](#0-4) 

### Impact Explanation

Traders executing swaps through any bin where the pool admin has set maximum bin additional fees pay up to 6.55 % more per swap than the protocol's admin fee cap is supposed to allow. The excess fee accrues as spread surplus in the pool and is collected by the admin via `collectPoolFees`. This is a direct, per-swap extraction of trader principal that bypasses the protocol's fee-cap invariant.

### Likelihood Explanation

The pool admin is a semi-trusted role. The factory explicitly caps all other admin fee vectors (`setPoolAdminFees`), establishing a clear protocol invariant that admin fees must not exceed `maxAdminSpreadFeeE6`. A pool admin who wishes to extract more than the cap allows has a straightforward, unprivileged-within-their-role path: call `setPoolBinAdditionalFees` with `addFeeBuyE6 = type(uint16).max` on every bin. No timelock, no owner approval, no additional precondition.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, define a dedicated `maxAdminBinAdditionalFeeE6` cap and enforce it here and in `setFeeCaps`.

### Proof of Concept

1. Factory owner deploys a pool with `maxAdminSpreadFeeE6 = 50_000` (5 %) and `adminSpreadFeeE6 = 50_000`.
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — no revert.
3. A trader calls `pool.swap(...)` routing through bin 0.
4. The effective buy fee is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — approximately 5 % (spread) + 6.55 % (bin) = 11.55 %, exceeding the 5 % admin cap.
5. The surplus (6.55 % of trade notional) accumulates as spread surplus and is collected by the admin via `factory.collectPoolFees(pool)`.

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
