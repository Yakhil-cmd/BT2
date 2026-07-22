Now I have a complete picture. Let me trace the full execution path.

The code trace is complete. Here is the determination:

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`, while the parallel admin fee setter `setPoolAdminFees` enforces that cap. A pool admin can set per-bin fees to `type(uint16).max` (65 535, i.e. ~6.55% in E6 units), causing every swap through that bin to pay a spread far exceeding the factory-configured admin cap.

### Finding Description

`setPoolAdminFees` enforces the cap:

```solidity
// MetricOmmPoolFactory.sol:414
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has no such check — it forwards the raw caller-supplied values straight to the pool:

```solidity
// MetricOmmPoolFactory.sol:450-456
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` stores the values without any cap check:

```solidity
// MetricOmmPool.sol:464-474
s.addFeeBuyE6  = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

During every swap the per-bin fee is added directly to the oracle-derived base fee before the swap math runs:

```solidity
// MetricOmmPool.sol:999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
``` [4](#0-3) 

```solidity
// MetricOmmPool.sol:1177
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
``` [5](#0-4) 

The per-bin fee widens the effective bid/ask spread charged to the trader. With `addFeeBuyE6 = type(uint16).max = 65 535`, the additional spread is ~6.55 %, regardless of what `maxAdminSpreadFeeE6` is set to (which can be as low as 0 by the factory owner).

### Impact Explanation

Traders swapping through the affected bin pay a spread that includes the uncapped per-bin fee on top of the oracle spread. This is a direct, quantifiable loss of trader principal to the pool (the excess fee accrues as LP fee revenue). The factory owner's `maxAdminSpreadFeeE6` governance control is rendered ineffective for the per-bin fee vector, which is an explicit admin-boundary break called out in the Smart Audit Pivots.

### Likelihood Explanation

The pool admin is a semi-trusted role. The factory owner sets `maxAdminSpreadFeeE6` precisely to constrain what a pool admin can charge. A pool admin who turns malicious (or whose key is compromised) can immediately call `setPoolBinAdditionalFees` with `type(uint16).max` on every active bin, with no timelock and no cap enforcement. No other on-chain guard prevents this.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
if (uint256(addFeeBuyE6)  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (uint256(addFeeSellE6) > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

Alternatively, enforce the same check inside `MetricOmmPool.setBinAdditionalFees` using the factory-supplied cap, or introduce a dedicated `maxAdminBinFeeE6` cap.

### Proof of Concept

1. Deploy factory with `maxAdminSpreadFeeE6 = 1000` (0.1 %).
2. Create a pool; pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, type(uint16).max, type(uint16).max)`.
3. No revert occurs; `_binStates[0].addFeeBuyE6 == 65535`.
4. Execute a swap through bin 0; the effective fee applied is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — approximately 6.55 % additional spread — far exceeding the 0.1 % admin cap.
5. Assert that the fee charged to the trader exceeds `maxAdminSpreadFeeE6`; assertion passes, confirming the cap is bypassed.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
