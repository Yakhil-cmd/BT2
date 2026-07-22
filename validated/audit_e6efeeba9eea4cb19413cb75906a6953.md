The vulnerability is real. Here is the complete analysis:

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` (both `uint16`, max 65535) directly to the pool with no validation against `maxAdminSpreadFeeE6`. The pool's `setBinAdditionalFees` also performs no cap check. These per-bin fees are added directly to `baseFeeX64` in every swap through the affected bin, so a pool admin can impose up to 6.5535% additional spread per bin — far exceeding any configured `maxAdminSpreadFeeE6` — causing traders to pay fees well above the factory-enforced cap.

### Finding Description

`setPoolAdminFees` correctly enforces the cap:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` has no such guard — it forwards the raw caller-supplied values straight to the pool:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` also performs no cap check — it writes the values directly to `BinState`:

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
``` [3](#0-2) 

During every swap, the per-bin fee is added directly to `baseFeeX64` before computing the effective bid/ask price:

```solidity
// MetricOmmPool.sol:910
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
``` [4](#0-3) 

```solidity
// MetricOmmPool.sol:1088
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
``` [5](#0-4) 

The same uncapped values are used in `getSellAndBuyPrices` (the price-quoting path):

```solidity
// MetricOmmPool.sol:540-541
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [6](#0-5) 

### Impact Explanation

A pool admin can call `setPoolBinAdditionalFees(pool, bin, 65535, 65535)` on any or all bins. With `uint16` max = 65535, the per-bin additional fee is 65535/1e6 ≈ **6.5535%** per bin, additive on top of the oracle-derived base spread. This is completely uncapped regardless of `maxAdminSpreadFeeE6` (which the factory owner may have set to e.g. 1000 = 0.1%). Every trader swapping through the affected bin pays this inflated fee. The factory's fee-cap invariant — the primary protection against pool-admin overreach — is broken. This constitutes bad-price execution and direct loss of trader principal on every swap through the affected bin.

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly constrained by `maxAdminSpreadFeeE6`. The bypass requires only a single transaction from the pool admin with no timelock. Any pool admin (including a compromised or malicious one) can exploit this immediately after pool creation. The `setPoolBinAdditionalFees` function is a standard pool-admin entrypoint with no special preconditions.

### Recommendation

Add a cap check in `MetricOmmPoolFactory.setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (uint24(addFeeBuyE6) > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (uint24(addFeeSellE6) > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

### Proof of Concept

1. Deploy `MetricOmmPoolFactory` with `maxAdminSpreadFeeE6 = 1000` (0.1%).
2. Create a pool with `adminSpreadFeeE6 = 1000` (at the cap).
3. As pool admin, call `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
4. Read `BinState` for bin 0: `addFeeBuyE6 == 65535`, `addFeeSellE6 == 65535` — no revert.
5. Execute a swap through bin 0; the effective fee applied is `baseFeeX64 + 65535/1e6` ≈ 6.5535% additional spread, far exceeding the 0.1% cap.
6. Assert that the trader receives significantly less than they would under the capped fee, confirming direct fund loss above Sherlock thresholds.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
