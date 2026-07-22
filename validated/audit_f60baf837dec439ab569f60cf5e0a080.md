### Title
Pool Admin Can Set Per-Bin Additional Fees Without Any Upper-Bound Check, Bypassing the Protocol Fee Cap System - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` and `addFeeSellE6` directly to `MetricOmmPool.setBinAdditionalFees` with no upper-bound validation. The pool admin can set these to any `uint16` value (max 65,535 = 6.5535% in E6 units), bypassing the protocol's fee cap system that governs all other admin-controlled fees.

### Finding Description
The protocol enforces a hard fee cap (`HARD_MAX_SPREAD_FEE_E6 = 200,000`, i.e. 20%) on all admin-controlled spread fees via `setPoolAdminFees`:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

However, `setPoolBinAdditionalFees` performs no analogous check:

```solidity
// MetricOmmPoolFactory.sol:450-456
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

`MetricOmmPool.setBinAdditionalFees` also performs no cap check, writing the values directly to storage:

```solidity
// MetricOmmPool.sol:464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
```

These per-bin fees are then added directly to the oracle base fee in every swap path:

```solidity
// MetricOmmPool.sol:540-541
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

The ask price paid by a buyer is then:
```solidity
// MetricOmmPool.sol:543
uint256 askBeforeNotional = Math.mulDiv(marginalPriceX64, ONE_X64 + buyFeeX64, ONE_X64, Math.Rounding.Ceil);
```

A pool admin can set `addFeeBuyE6 = 65535` (the `uint16` maximum, equal to 6.5535% in E6 units) for any active bin. This additional fee is applied on top of the oracle spread fee and the notional fee, with no validation against `maxAdminSpreadFeeE6` or `HARD_MAX_SPREAD_FEE_E6`. The same unchecked path exists at pool creation time: `_unpackAndValidateBinStates` unpacks `addFeeBuyE6`/`addFeeSellE6` from the packed bin arrays and stores them without any cap check.

### Impact Explanation
Traders swapping through the affected bin pay an additional fee of up to 6.5535% on top of the oracle spread and notional fee, with no on-chain bound. This is a direct loss of user principal: the trader receives less output (or pays more input) than the protocol's fee cap system is supposed to allow. The pool admin is semi-trusted only within caps; this path lets the admin impose uncapped per-bin fees that are invisible to the factory's fee accounting and cannot be detected by inspecting `poolFeeConfig`.

### Likelihood Explanation
The pool admin is a valid, non-privileged-beyond-caps actor who can call `setPoolBinAdditionalFees` at any time with no preconditions. The active bin changes as the price moves, so the admin can target whichever bin is currently active. No special market conditions are required.

### Recommendation
Add an upper-bound check in `MetricOmmPoolFactory.setPoolBinAdditionalFees` before forwarding to the pool, analogous to the check in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Apply the same cap check to the bin arrays unpacked in `_unpackAndValidateBinStates` during `createPool`.

### Proof of Concept
1. Pool is deployed with `spreadFeeE6 = 200_000` (20%, at the hard cap) and `notionalFeeE8 = 1_000_000` (1%).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, curBinIdx, 65535, 65535)`.
3. No revert occurs; `addFeeBuyE6 = 65535` is stored on the bin.
4. A trader calls `swap(zeroForOne=true, amountSpecified=X)`. The swap math computes:
   - `buyFeeX64 = baseFeeX64 + 65535 * ONE_X64 / 1e6` — an additional ~6.5535% on top of the oracle spread.
   - `askBeforeNotional = marginalPriceX64 * (ONE_X64 + buyFeeX64) / ONE_X64` — price inflated by the uncapped fee.
5. The trader pays ~6.5535% more than the oracle-derived price permits, with no on-chain guard preventing it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L413-415)
```text
  {
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-544)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);

    uint256 askBeforeNotional = Math.mulDiv(marginalPriceX64, ONE_X64 + buyFeeX64, ONE_X64, Math.Rounding.Ceil);
    uint256 bidAfterSpread = Math.mulDiv(marginalPriceX64, ONE_X64, ONE_X64 + sellFeeX64, Math.Rounding.Floor);
```
