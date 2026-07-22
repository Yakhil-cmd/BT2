### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees via `setPoolBinAdditionalFees`, Bypassing the Global Spread Fee Cap — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

---

### Summary

`setPoolBinAdditionalFees` in `MetricOmmPoolFactory` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool with **no cap validation**, while the analogous global admin spread fee setter (`setPoolAdminFees`) is strictly bounded by `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to `type(uint16).max` (65,535 in E6 units ≈ 6.55%) on any active bin, silently charging traders more than the protocol's intended hard ceiling.

---

### Finding Description

The factory enforces a layered fee cap system. The factory owner sets `maxAdminSpreadFeeE6` (≤ `HARD_MAX_SPREAD_FEE_E6` = 200,000 = 20%), and `setPoolAdminFees` reverts if the new admin spread fee exceeds that cap: [1](#0-0) 

However, the pool-admin path for per-bin fees performs **no equivalent check**: [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap check — it only validates the bin index: [3](#0-2) 

During every swap, the bin additional fee is added directly on top of the oracle-derived base fee before the swap math executes: [4](#0-3) 

The same additive pattern appears in `getSellAndBuyPrices`: [5](#0-4) 

Because `addFeeBuyE6` / `addFeeSellE6` are `uint16`, the pool admin can set them to 65,535 (≈ 6.55% in E6 units) on any bin without any factory-level guard. This is additive on top of the already-capped global `spreadFeeE6` (≤ 20%), so the effective per-bin fee can reach ≈ 26.55% — well above the hard ceiling the protocol intends to enforce.

---

### Impact Explanation

Traders swapping through a bin where the pool admin has set `addFeeBuyE6` or `addFeeSellE6` to the maximum `uint16` value receive materially less output than the global fee cap would permit. The excess fee (up to ≈ 6.55%) is extracted from the trader's swap output and accrues to LP positions in that bin, constituting a direct loss of user principal. For a $1 M swap, the uncapped excess alone can reach ≈ $65,000.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly scoped to operate only within factory-enforced caps. The `setPoolBinAdditionalFees` path is callable by any current `poolAdmin[pool]` with no timelock and no cap guard. A malicious or compromised pool admin can silently raise per-bin fees to the uint16 maximum at any time, affecting all subsequent swaps through that bin without any on-chain signal beyond the `BinAdditionalFeesUpdated` event.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (and symmetrically in `createPool`'s `_unpackAndValidateBinStates`) so that `addFeeBuyE6` and `addFeeSellE6` cannot exceed a factory-controlled maximum (e.g., `maxAdminSpreadFeeE6`, or a dedicated `maxBinAdditionalFeeE6` cap). The pool's `setBinAdditionalFees` should also enforce the same bound as a defence-in-depth check.

```solidity
// In MetricOmmPoolFactory.setPoolBinAdditionalFees:
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
```

---

### Proof of Concept

1. Pool is created with `adminSpreadFeeE6 = 5_000` (0.5%) and `maxAdminSpreadFeeE6 = 200_000` (20%).
2. Pool admin calls `factory.setPoolAdminFees(pool, 200_000, 0)` — succeeds, capped at 20%.
3. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — **succeeds with no revert**, setting per-bin buy and sell additional fees to ≈ 6.55% each.
4. A trader swaps through bin 0. The effective fee applied is `baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)` — approximately 6.55% above the oracle spread, on top of the 20% global spread fee, for a total of ≈ 26.55%.
5. The trader receives ≈ 6.55% less output than the protocol's hard cap would allow, with no on-chain revert or warning. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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
