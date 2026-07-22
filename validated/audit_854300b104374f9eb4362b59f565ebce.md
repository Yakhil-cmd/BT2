### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` forwards per-bin fee values to the pool with **no validation against `maxAdminSpreadFeeE6`**, allowing a pool admin to impose effective swap fees that exceed the factory-enforced cap. This is the direct analog of the external report: a value is written to state without being clamped to the applicable maximum.

---

### Finding Description

The factory enforces an admin spread-fee cap in `setPoolAdminFees`: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

The parallel path `setPoolBinAdditionalFees` has **no such check**: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` also performs no cap validation — it only checks the bin index: [3](#0-2) 

```solidity
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

In the swap path, bin additional fees are added **on top of** the base spread fee: [4](#0-3) 

```solidity
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

`addFeeBuyE6` and `addFeeSellE6` are `uint16`, so they can be set to **65 535** (≈ 6.55 %) per bin with no factory-level guard. This is additive to the already-capped spread fee, so the total effective fee charged to traders can exceed `maxAdminSpreadFeeE6` by up to 6.55 percentage points.

---

### Impact Explanation

Traders pay more in swap fees than the factory-enforced cap permits. The excess fee accrues inside the pool as LP revenue (benefiting LPs, which may include the pool admin). This is a direct, quantifiable loss of user principal on every swap through an affected bin, and it violates the admin-boundary invariant that the factory is designed to enforce.

---

### Likelihood Explanation

Medium. Any pool admin — a semi-trusted role — can call `setPoolBinAdditionalFees` at any time with no timelock. No additional privilege or external condition is required. The bypass is permanent until the factory owner intervenes (which requires a separate privileged action).

---

### Recommendation

Add cap validation inside `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

---

### Proof of Concept

1. Factory owner sets `maxAdminSpreadFeeE6 = 10_000` (1 %) via `setFeeCaps`.
2. Pool admin calls `setPoolAdminFees(pool, 10_000, 0)` — accepted, exactly at the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` — **no revert**, values written directly to `_binStates[0]`.
4. A trader swaps through bin 0 and is charged ≈ 1 % (spread) + 6.55 % (bin additional) = **7.55 % total**, far exceeding the 1 % cap the factory advertises.
5. The excess 6.55 % accrues to LPs inside the pool; it is not recoverable by the protocol or the trader.

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
