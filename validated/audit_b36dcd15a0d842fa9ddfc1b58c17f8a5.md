### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped Per-Bin Additional Fees — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` caps on admin-controlled fees via `setPoolAdminFees`, but `setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` (`uint16`, max 65 535 = 6.5535 % in E6 units) directly to the pool with **no cap validation**. A pool admin can set per-bin additional fees to the `uint16` ceiling for every bin, charging traders fees that far exceed the protocol-enforced admin cap — including when that cap is zero.

---

### Finding Description

The factory stores two hard limits that bound what a pool admin may charge: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

These checks appear only in `setPoolAdminFees`. The sibling function `setPoolBinAdditionalFees` has **no equivalent guard**: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool-side handler likewise performs no cap check — only a bin-index range check: [3](#0-2) 

```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
```

During every swap these per-bin values are **added on top of** the base spread fee: [4](#0-3) 

```solidity
uint256 buyFeeX64  = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6,  ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

`uint16.max = 65 535` → 6.5535 % in E6 units. A pool admin can call `setPoolBinAdditionalFees` once per bin (up to 256 bins) and immediately impose a 6.5535 % surcharge on every swap through those bins, regardless of what `maxAdminSpreadFeeE6` is set to — even if it is zero.

---

### Impact Explanation

Every trader who swaps through an affected bin pays up to 6.5535 % more than the protocol-enforced cap permits. Because the per-bin fee is charged on the **output token** (exact-in) or the **input notional** (exact-out), the excess is a direct, real-time transfer of value from traders to the pool admin's fee destination. This constitutes a direct loss of user principal above Sherlock thresholds and is an admin-boundary break: the pool admin exceeds the `maxAdminSpreadFeeE6` cap without any privileged escalation.

---

### Likelihood Explanation

The pool admin is semi-trusted only within caps and timelocks. No timelock protects `setPoolBinAdditionalFees`; the call is executable in a single transaction. A compromised or malicious pool admin key can silently raise effective fees to the `uint16` ceiling for all bins before any LP or trader can react. The factory owner has no direct mechanism to override per-bin fees without going through the pool admin path.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` (factory side) mirroring the check in `setPoolAdminFees`:

```solidity
if (addFeeBuyE6  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap that the factory owner can configure independently, so that fine-grained per-bin control is preserved while the ceiling remains enforced.

---

### Proof of Concept

1. Factory owner deploys factory with `maxAdminSpreadFeeE6 = 0` (admin must charge zero global spread).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. No revert — `addFeeBuyE6` and `addFeeSellE6` are stored as 65 535 on bin 0.
4. A trader calls `pool.swap(...)` routing through bin 0; the effective buy fee becomes `baseFeeX64 + 65535 * ONE_X64 / 1e6` ≈ 6.55 % above the oracle mid-price.
5. The excess fee accrues as spread surplus and is collected to `poolAdminFeeDestination` on the next `collectPoolFees` call — bypassing the `maxAdminSpreadFeeE6 = 0` constraint entirely. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
