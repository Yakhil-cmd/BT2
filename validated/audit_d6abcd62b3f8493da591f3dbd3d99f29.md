### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` on the global admin spread component, but `setPoolBinAdditionalFees` forwards per-bin `addFeeBuyE6`/`addFeeSellE6` values directly to the pool with no cap check. A pool admin can set per-bin additional fees up to `uint16` max (65 535 in E6 units = 6.5535%) on every bin regardless of what `maxAdminSpreadFeeE6` is set to, bypassing the protocol-owner-controlled fee ceiling entirely.

### Finding Description

`setPoolAdminFees` guards the global admin spread component:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees`, callable by the same pool admin role, performs no analogous check:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool-level `setBinAdditionalFees` also applies no cap — it only validates the bin index range: [3](#0-2) 

During every swap, the per-bin additional fee is added directly to `baseFeeX64` before the swap math executes:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
``` [4](#0-3) 

`BinState.addFeeBuyE6` and `addFeeSellE6` are `uint16`, so the unchecked ceiling is 65 535 (≈ 6.55 %) per bin: [5](#0-4) 

The hard cap on the global admin spread is `HARD_MAX_SPREAD_FEE_E6 = 200 000` (20 %), and the owner can lower `maxAdminSpreadFeeE6` to any value including 0: [6](#0-5) 

### Impact Explanation

When the protocol owner lowers `maxAdminSpreadFeeE6` (e.g. to 0 to signal a fee-free pool), the pool admin can still call `setPoolBinAdditionalFees` on every active bin and set `addFeeBuyE6 = addFeeSellE6 = 65535`. Every subsequent swap through those bins pays up to 6.55 % extra spread on top of the oracle-derived base fee. The excess spread accrues as pool surplus and is collected proportionally by protocol and admin via `collectFees`. Traders suffer direct principal loss on every swap; the effective fee ceiling the owner intended to enforce is silently violated.

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly constrained by `maxAdminSpreadFeeE6`. The bypass requires only a single call to `setPoolBinAdditionalFees` with `addFeeBuyE6`/`addFeeSellE6` set above the cap — no special timing, no flash loan, no multi-step setup. Any pool admin who wishes to extract more than the owner-approved fee ceiling can do so immediately and on every bin.

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Equivalently, apply the same check at pool creation time inside `_unpackAndValidateBinStates` for the initial per-bin fees packed in `nonNegativeBinDataArray` / `negativeBinDataArray`.

### Proof of Concept

1. Owner deploys factory and sets `maxAdminSpreadFeeE6 = 0` (zero admin spread cap).
2. Pool admin calls `setPoolAdminFees(pool, 0, 0)` — succeeds, global admin spread is 0.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — succeeds with no revert.
4. A trader calls `swap(...)` through bin 0. The effective fee applied is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — approximately 6.55 % above the oracle mid-price — far exceeding the 0 % cap the owner intended.
5. The surplus from the inflated spread is collected via `collectPoolFees`, with the admin's share flowing to `poolAdminFeeDestination`. [7](#0-6) [2](#0-1)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1178)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
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
