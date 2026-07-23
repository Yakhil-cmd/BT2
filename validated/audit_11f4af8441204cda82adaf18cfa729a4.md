The claim is factually correct and constitutes a real admin-boundary break. Here is the full analysis:

---

### Title
Pool Admin Can Set Uncapped Per-Bin Additional Fees Up to uint16 Max (~6.55%), Bypassing Factory Fee Cap System — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` and `addFeeSellE6` directly to `pool.setBinAdditionalFees` with no upper-bound check, while the analogous `setPoolAdminFees` path enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to `uint16` max (65535 E6 ≈ 6.55%) on any bin, causing every swap through that bin to pay an uncapped additional fee on top of the spread fee.

---

### Finding Description

`setPoolAdminFees` explicitly enforces factory-configured caps:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has no equivalent check — it passes values straight through:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool-side `setBinAdditionalFees` only validates the bin index, not the fee magnitude:

```solidity
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

A grep for any `maxAdminBin`, `maxBinFee`, or `maxAddFee` cap returns zero matches — no such cap exists anywhere in the factory or pool.

The stored `addFeeBuyE6` is consumed directly in every swap through that bin:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) [5](#0-4) 

Setting `addFeeBuyE6 = 65535` adds `65535 / 1e6 ≈ 6.55%` to the effective fee for every swap through that bin, on top of the global spread fee.

---

### Impact Explanation

Every trader whose swap routes through the affected bin pays up to ~6.55% additional fee beyond the factory-capped spread fee. This is a direct extraction of trader principal. The pool admin can target the active bin (bin 0 or the bin currently holding liquidity) to maximize impact on all live swaps. This exceeds Sherlock medium thresholds for direct loss of user funds.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly expected to operate only within factory-enforced caps. The call path is a single transaction with no timelock. Any pool admin — including one who turns adversarial after deployment — can execute this immediately. The `setPoolAdminFees` cap pattern demonstrates the design intent was to bound admin fee power; the omission in `setPoolBinAdditionalFees` is an inconsistency, not a deliberate design choice.

---

### Recommendation

Add a factory-level cap for bin additional fees, analogous to `maxAdminSpreadFeeE6`. Introduce a `maxAdminBinAdditionalFeeE6` storage variable (set by the factory owner via `setFeeCaps` or a dedicated setter), and enforce it in `setPoolBinAdditionalFees`:

```solidity
if (addFeeBuyE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminBinAdditionalFeeE6) revert AdminFeeTooHigh();
```

---

### Proof of Concept

```solidity
// Foundry test
function test_binAdditionalFee_uncapped() public {
    address pool = _createPool(); // maxAdminSpreadFeeE6 = e.g. 50_000 (5%)

    vm.prank(admin);
    // Set addFeeBuyE6 to uint16 max — no revert, no cap check
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Execute a swap through bin 0
    // Assert effective fee charged ≈ spreadFeeE6 + 6.55%
    // which far exceeds maxAdminSpreadFeeE6
}
```

The call succeeds because `setPoolBinAdditionalFees` contains no cap check, while `setPoolAdminFees` with the same value would revert with `AdminFeeTooHigh`. [2](#0-1) [1](#0-0)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L469-473)
```text
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```
