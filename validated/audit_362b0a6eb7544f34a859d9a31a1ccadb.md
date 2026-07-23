### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees, Bypassing the Fee Cap System - (`metric-core/contracts/MetricOmmPoolFactory.sol`, `metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`setPoolBinAdditionalFees` imposes no upper bound on `addFeeBuyE6` / `addFeeSellE6`, while every other pool-admin fee path is explicitly capped. A pool admin can set either value to `uint16` max (65 535, i.e. 6.5535 % in E6 notation) and the pool's swap math adds it directly on top of the oracle-derived base spread, causing traders to pay fees that exceed the hard cap the factory was designed to enforce.

---

### Finding Description

The factory enforces a hard ceiling of `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %) on all global spread fees. [1](#0-0) 

`setPoolAdminFees` respects this cap: [2](#0-1) 

`setPoolBinAdditionalFees` does not — it passes the caller-supplied values straight through to the pool with only a bin-index range check: [3](#0-2) 

The pool stores them without validation: [4](#0-3) 

During every swap the per-bin value is added directly to `baseFeeX64` before computing the effective ask/bid price: [5](#0-4) 

The same addition appears in all four swap paths (`buyToken0InBinSpecifiedIn/Out`, `buyToken1InBinSpecifiedIn/Out`): [6](#0-5) [7](#0-6) [8](#0-7) 

`uint16` max is 65 535, which in E6 units equals **6.5535 %**. Combined with a base spread already at the 20 % hard cap, the effective per-bin fee reaches **26.5535 %** — 6.5535 percentage points above the hard ceiling the factory is supposed to enforce.

---

### Impact Explanation

Every trader whose swap routes through the manipulated bin pays the inflated fee. The excess is retained by the pool as LP spread surplus (collected by the admin via `collectPoolFees`), constituting a direct, quantifiable loss of trader principal. The effect is immediate — no timelock or delay is required — and persists until the admin resets the value.

---

### Likelihood Explanation

The pool admin role is semi-trusted: the factory explicitly caps their global spread and notional fees but provides no equivalent guard for per-bin fees. Any pool admin (a single EOA or multisig) can call `setPoolBinAdditionalFees` at any time on any bin, including the bin currently active for trading, with no on-chain friction.

---

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` in `MetricOmmPoolFactory`, mirroring the pattern used for global admin fees:

```solidity
// in setPoolBinAdditionalFees, before the pool call:
if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap that can be tuned independently of the global spread cap.

---

### Proof of Concept

```solidity
// 1. Pool admin sets per-bin additional fee to uint16 max on the active bin
factory.setPoolBinAdditionalFees(pool, activeBin, 65535, 65535);

// 2. Trader executes a buy-token0 swap through that bin.
//    Inside _swapToken1ForToken0SpecifiedInput the effective fee becomes:
//      baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)
//    = baseFeeX64 + 6.5535% (in X64 units)
//    The ask price is inflated by this amount, so the trader pays 6.5535%
//    more than the oracle-derived spread alone would require.

// 3. Assert: trader's token1 input > expected input at base spread alone.
//    Difference = 6.5535% of the notional traded through that bin.
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
