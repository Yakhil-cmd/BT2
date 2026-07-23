### Title
Pool Admin Can Set Per-Bin Additional Fees Without Any Cap Validation, Exceeding the Intended Admin Fee Ceiling - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool with no cap check, while the global admin spread fee is explicitly bounded by `maxAdminSpreadFeeE6`. A semi-trusted pool admin can set per-bin additional fees up to the `uint16` maximum (65,535 E6 units ≈ 6.55%) on any bin, imposing fees beyond the intended admin fee ceiling on every swap that crosses that bin.

### Finding Description

The factory enforces a hard cap on the global admin spread fee via `maxAdminSpreadFeeE6` (itself bounded by `HARD_MAX_SPREAD_FEE_E6 = 200_000`, i.e. 20%). However, `setPoolBinAdditionalFees` passes `addFeeBuyE6` and `addFeeSellE6` straight through to `setBinAdditionalFees` on the pool with only a bin-index range check and no fee-magnitude check:

```solidity
// MetricOmmPoolFactory.sol
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [1](#0-0) 

```solidity
// MetricOmmPool.sol
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The per-bin additional fee is then added directly to the oracle-derived base fee during every swap that crosses the bin:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
``` [3](#0-2) 

By contrast, the global admin spread fee is validated against `maxAdminSpreadFeeE6` in both `setPoolAdminFees` and `createPool`:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [4](#0-3) 

No equivalent guard exists for `addFeeBuyE6` / `addFeeSellE6`. The `uint16` type is the only constraint, allowing values up to 65,535 E6 units (≈ 6.55%).

### Impact Explanation

Every swap that crosses a bin with `addFeeBuyE6 = 65535` pays an additional ≈ 6.55% fee on top of the oracle spread fee. This fee is deducted from the swap output (or added to the input for exact-output swaps), constituting a direct loss of user principal. Because the pool admin can apply this to any or all bins simultaneously, the effective fee ceiling is bypassed for the entire pool's active price range. The `BinState` struct stores `addFeeBuyE6` and `addFeeSellE6` as `uint16`, so the corrupted values persist until the admin resets them. [5](#0-4) 

### Likelihood Explanation

The trigger is the pool admin, who is semi-trusted "only inside caps." The global admin spread fee cap is enforced, but the per-bin additional fee cap is absent. Any pool admin — including one acting maliciously or one whose key is compromised — can call `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535` in a single transaction with no timelock. The `collectPoolFees` path is permissionless, so the admin can also time fee collection to maximize extraction before resetting the per-bin fee. [6](#0-5) 

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and optionally in `setBinAdditionalFees` as a defense-in-depth guard) analogous to the existing `maxAdminSpreadFeeE6` check:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap that the factory owner can configure, mirroring the pattern used for `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8`.

### Proof of Concept

1. Factory deploys a pool with `adminSpreadFeeE6 = 0` and `maxAdminSpreadFeeE6 = 200_000` (20%).
2. Pool admin calls `factory.setPoolAdminFees(pool, 200_000, 0)` — accepted, at the cap.
3. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — accepted with no revert.
4. A swapper calls `pool.swap(...)` crossing bin 0. The effective buy fee is `baseFeeX64 + 65535/1e6 * ONE_X64`, i.e. oracle spread + ≈ 6.55% additional, exceeding the intended 20% global cap by an unchecked margin.
5. The swapper receives ≈ 6.55% less output than the oracle spread alone would imply, with no on-chain guard having prevented the admin from setting this value. [1](#0-0) [2](#0-1)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L379-389)
```text
  function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-540)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
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
