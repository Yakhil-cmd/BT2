### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards arbitrary `uint16` bin-level fee values to the pool with no cap check, while the parallel path `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can therefore bypass the factory owner's intended fee ceiling by routing through the bin-fee path instead of the pool-fee path.

### Finding Description

`setPoolAdminFees` enforces the factory owner's cap: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

`setPoolBinAdditionalFees` performs no such check — it passes the caller-supplied values directly to the pool: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` also performs no cap check: [3](#0-2) 

The bin additional fees are added directly to the effective swap fee during every swap: [4](#0-3) 

```solidity
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

`addFeeBuyE6` / `addFeeSellE6` are `uint16`, so the uncapped maximum is **65 535 (≈ 6.55 %)** per bin, regardless of what `maxAdminSpreadFeeE6` is set to.

### Impact Explanation

Traders swapping through any bin whose additional fee has been set to `type(uint16).max` pay up to 6.55 % extra on top of the base spread fee. This is a direct loss of swap output (or excess input) for every affected trade. The factory owner's `maxAdminSpreadFeeE6` cap — the only mechanism intended to bound admin-controlled fees — is completely ineffective against this path. Protocol fees collected by the factory are unaffected; the excess accrues as surplus inside the pool, accessible to the pool admin via `collectFees`.

### Likelihood Explanation

Any pool admin can call `setPoolBinAdditionalFees` at any time with no preconditions. No timelock, no governance vote, no special role beyond `poolAdmin[pool]`. The call is a single transaction. Because the factory registers every pool in `idxToPool` / `poolToIdx`, integrators and aggregators may treat factory-registered pools as having bounded fees, making this bypass non-obvious to downstream users. [5](#0-4) 

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` that mirrors the guard in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
+   if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
+   if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinFeeE6` cap and enforce it here and in `setFeeCaps`.

### Proof of Concept

1. Factory owner calls `setFeeCaps(…, newMaxAdminSpreadFeeE6 = 1_000, …)` — capping admin spread fees at 0.1 %.
2. Pool admin calls `setPoolAdminFees(pool, 1_001, …)` → reverts with `AdminFeeTooHigh`. Cap is enforced.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` → **succeeds**. Bin 0 now charges an extra 6.55 % buy and sell fee.
4. Any trader swapping through bin 0 pays 6.55 % more than the protocol-intended maximum, with the excess accumulating as pool surplus claimable by the admin. [6](#0-5) [2](#0-1)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L149-151)
```text
  function isPool(address pool) external view override returns (bool) {
    return poolToIdx[pool] != 0;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
