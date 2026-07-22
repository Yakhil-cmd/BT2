The code evidence is conclusive. Let me trace the exact path:

**`setPoolAdminFees`** enforces the cap: [1](#0-0) 

**`setPoolBinAdditionalFees`** has no cap check at all — it passes the raw `uint16` straight through: [2](#0-1) 

**`setBinAdditionalFees`** on the pool also has no cap check — only a bin-range check: [3](#0-2) 

The uncapped `addFeeBuyE6` is then added directly to `baseFeeX64` in every swap direction: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

`HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) is the hard cap for the global spread fee: [8](#0-7) 

`addFeeBuyE6` is `uint16` (max 65535 = 6.5535%) with no cap check in `setPoolBinAdditionalFees`. This is a real admin-boundary break: the pool admin is supposed to be bounded by `maxAdminSpreadFeeE6`, but the per-bin fee path has no such constraint.

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`setPoolBinAdditionalFees` applies no cap check on `addFeeBuyE6`/`addFeeSellE6`, allowing the pool admin to set per-bin fees up to `uint16` max (65535 = 6.5535%) on every bin, bypassing the `maxAdminSpreadFeeE6` invariant that is enforced on the global admin spread fee path.

### Finding Description
The factory enforces `maxAdminSpreadFeeE6` in `setPoolAdminFees` but not in `setPoolBinAdditionalFees`. A pool admin can call `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` for every bin in `[LOWEST_BIN, HIGHEST_BIN]` without any revert. The uncapped value is written directly to `BinState.addFeeBuyE6`/`addFeeSellE6` and is added to `baseFeeX64` in all four swap paths (`_swapToken1ForToken0SpecifiedOutput`, `_swapToken1ForToken0SpecifiedInput`, `_swapToken0ForToken1SpecifiedOutput`, `_swapToken0ForToken1SpecifiedInput`) with no downstream clamping.

### Impact Explanation
Traders executing multi-bin swaps pay 6.5535% additional fee per bin traversed on top of the global spread fee, far exceeding the `maxAdminSpreadFeeE6` bound. This is a direct loss of trader principal above Sherlock thresholds. The pool admin can drain value from every swap without the protocol's fee-cap governance having any effect.

### Likelihood Explanation
The pool admin is a semi-trusted role that is explicitly expected to be bounded by `maxAdminSpreadFeeE6`. The bypass requires only a loop of `setPoolBinAdditionalFees` calls — no special conditions, no timelock, no oracle manipulation. Any pool admin can execute this immediately after pool creation.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` (or in `setBinAdditionalFees` on the pool) that enforces `addFeeBuyE6 <= maxAdminSpreadFeeE6` and `addFeeSellE6 <= maxAdminSpreadFeeE6`, consistent with the cap enforced in `setPoolAdminFees`.

### Proof of Concept
```solidity
// Pool admin loops over all bins and sets max uint16 fee
for (int8 bin = LOWEST_BIN; bin <= HIGHEST_BIN; bin++) {
    factory.setPoolBinAdditionalFees(pool, bin, 65535, 65535);
}
// Trader performs a multi-bin swap
// Actual output is far below what maxAdminSpreadFeeE6 would imply
// Each bin traversed charges 6.5535% additional fee on top of global spread
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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
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
