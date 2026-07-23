### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces `maxAdminSpreadFeeE6` on `setPoolAdminFees` but applies **no equivalent cap** to per-bin additional fees set via `setPoolBinAdditionalFees`. A pool admin can set `addFeeBuyE6` / `addFeeSellE6` to any value up to `type(uint16).max = 65 535` (≈ 6.55 % in E6 units) regardless of the factory owner's configured cap, causing traders to pay fees far above the intended ceiling.

---

### Finding Description

The factory owner controls the maximum admin fee through `maxAdminSpreadFeeE6`, which is itself bounded by the hardcoded constant `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %). [1](#0-0) 

`setPoolAdminFees` correctly enforces this cap: [2](#0-1) 

However, `setPoolBinAdditionalFees` passes the caller-supplied values straight through to the pool with **no cap check**: [3](#0-2) 

The pool's `setBinAdditionalFees` likewise performs no bounds check beyond the bin-index range: [4](#0-3) 

These per-bin fees are then added directly on top of the oracle-derived base fee in every swap step: [5](#0-4) 

The same gap exists at pool creation: `_validatePoolParameters` checks `adminSpreadFeeE6` and `adminNotionalFeeE8` against their caps but never validates the `addFeeBuyE6` / `addFeeSellE6` values packed into the bin arrays: [6](#0-5) 

---

### Impact Explanation

`uint16` allows values up to 65 535, which in E6 units equals **6.5535 %**. If the factory owner sets `

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L555-558)
```text
    if (spreadProtocolFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (protocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
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
