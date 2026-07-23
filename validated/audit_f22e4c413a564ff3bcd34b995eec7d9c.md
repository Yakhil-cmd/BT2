### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary
`setPoolBinAdditionalFees` lets the pool admin write arbitrary `addFeeBuyE6` / `addFeeSellE6` values into any bin with no check against `maxAdminSpreadFeeE6`. The cap that is enforced on the base admin spread fee in `setPoolAdminFees` is therefore silently bypassed through the bin-level path, allowing a semi-trusted pool admin to impose effective swap fees that exceed the factory-guaranteed ceiling.

---

### Finding Description

The factory maintains `maxAdminSpreadFeeE6` as the hard ceiling on the admin-controlled portion of the spread fee. `setPoolAdminFees` enforces this correctly: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

However, the parallel pool-admin entry point `setPoolBinAdditionalFees` performs **no such check**: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` likewise applies no cap: [3](#0-2) 

During every swap, the per-bin additional fee is added directly on top of the base spread fee when computing the effective buy/sell price: [4](#0-3) 

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

The effective admin-controlled fee for a swap in bin `b` is therefore `adminSpreadFeeE6 + addFeeBuyE6[b]`, which can exceed `maxAdminSpreadFeeE6` without any revert.

The `uint16` type bounds `addFeeBuyE6` / `addFeeSellE6` to at most 65 535 (≈ 6.55 % in E6 units). When `maxAdminSpreadFeeE6` is set below 65 535 — a realistic and common configuration — the pool admin can push the combined per-bin admin fee above the cap.

---

### Impact Explanation

Every swap routed through the affected bin pays a higher fee than the factory cap guarantees. Users who evaluate a pool's trustworthiness by inspecting `maxAdminSpreadFeeE6` are misled: the actual fee they pay can exceed that ceiling by up to 6.55 percentage points. This is a direct, repeatable loss of user principal on each swap, satisfying the contest's Medium/High loss threshold for pools with meaningful volume.

---

### Likelihood Explanation

The pool admin role is semi-trusted and explicitly bounded by caps per the README: *"Cannot exceed caps or bypass timelocks. If they can exceed caps … it can be valid."* No timelock, no co-signer, and no additional precondition is required — a single `setPoolBinAdditionalFees` call suffices. The attack is available from pool creation onward.

---

### Recommendation

Add a cap check inside `setPoolBinAdditionalFees` (or propagate the cap into `setBinAdditionalFees` on the pool):

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the combined invariant `adminSpreadFeeE6 + addFeeBuyE6 ≤ maxAdminSpreadFeeE6` if the intent is that the two levers share a single ceiling.

---

### Proof of Concept

1. Factory owner calls `setFeeCaps(…, newMaxAdminSpreadFeeE6 = 10_000, …)` — admin cap is 1 %.
2. Pool admin calls `setPoolAdminFees(pool, 10_000, 0)` — accepted, exactly at the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — **no revert**, accepted.
4. Any swap through bin 0 now incurs `adminSpreadFeeE6 = 10_000` **plus** `addFeeBuyE6 = 65_535` ≈ **7.55 % total admin-controlled fee**, far exceeding the 1 % cap the factory is supposed to enforce. [2](#0-1) [3](#0-2) [4](#0-3)

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
