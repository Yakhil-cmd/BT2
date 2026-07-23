### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolBinAdditionalFees` forwards per-bin fee values directly to the pool with no validation against the factory owner's `maxAdminSpreadFeeE6` cap. Every other admin fee-setting path enforces the cap; this one does not, allowing a pool admin to impose per-bin fees up to `uint16.max` (65 535 = 6.5535 % in E6 units) regardless of what the factory owner has configured.

### Finding Description

The factory enforces a two-level fee cap hierarchy. The factory owner calls `setFeeCaps` to set `maxAdminSpreadFeeE6`, which is then checked in every admin fee mutation:

`setPoolAdminFees` checks the cap before writing: [1](#0-0) 

`setPoolProtocolFee` also clamps admin fees to the current cap before forwarding: [2](#0-1) 

`setPoolBinAdditionalFees`, however, performs **no cap check at all** — it passes the caller-supplied `uint16` values straight through to the pool: [3](#0-2) 

The pool's `setBinAdditionalFees` likewise applies no cap; it only validates the bin index: [4](#0-3) 

During every swap, the per-bin additional fee is added directly on top of the oracle-derived base fee: [5](#0-4) 

The same addition appears in the live swap paths: [6](#0-5) [7](#0-6) 

### Impact Explanation

A pool admin can set `addFeeBuyE6` or `addFeeSellE6` to `uint16.max` (65 535 ≈ 6.55 %) on any bin, regardless of whether the factory owner has set `maxAdminSpreadFeeE6` to a lower value (e.g. 0, 1 000, 10 000). Every trader whose swap crosses that bin pays the uncapped additional fee on top of the normal spread. The excess fee accrues as pool surplus and is collected by the admin and protocol, constituting a direct loss of trader principal beyond the protocol-enforced maximum.

### Likelihood Explanation

The pool admin role is semi-trusted and is explicitly expected to be constrained by the factory owner's caps. Any pool admin can call `setPoolBinAdditionalFees` at any time with no preconditions, no timelock, and no special setup. The bypass is immediately exploitable on any pool whose admin is malicious or compromised.

### Recommendation

Add the same cap guard that `setPoolAdminFees` uses before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
+   if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
+   if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

### Proof of Concept

1. Factory owner calls `setFeeCaps(0, 500, 0, 0)` — capping admin spread fee at 0.05 %.
2. Pool admin calls `setPoolAdminFees(pool, 600, 0)` → reverts with `AdminFeeTooHigh`. Cap is enforced.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` → **succeeds**. Per-bin buy/sell fees are now 6.5535 %, 130× the cap.
4. Any trader swapping through bin 0 pays 6.5535 % additional fee on top of the oracle spread, far exceeding the factory owner's intended limit.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L339-346)
```text
    if (aSpread > maxAdminSpreadFeeE6) {
      aSpread = maxAdminSpreadFeeE6;
      emit PoolAdminSpreadFeeUpdated(pool, aSpread);
    }
    if (aNotional > maxAdminNotionalFeeE8) {
      aNotional = maxAdminNotionalFeeE8;
      emit PoolAdminNotionalFeeUpdated(pool, aNotional);
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L909-911)
```text
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
```

**File:** metric-core/contracts/MetricOmmPool.sol (L998-1000)
```text
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
```
