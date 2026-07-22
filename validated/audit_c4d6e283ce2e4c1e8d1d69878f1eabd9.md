### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`. The parallel function `setPoolAdminFees` does enforce the cap, but `setPoolBinAdditionalFees` does not, creating an asymmetric admin-boundary bypass.

### Finding Description

`setPoolAdminFees` correctly guards the cap:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` performs no such check — it passes the caller-supplied `uint16` values straight through:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` also performs no cap check — it writes the values directly to `BinState`:

```solidity
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

The per-bin fees are then added directly to the effective swap fee on every swap through that bin:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6)
``` [4](#0-3) 

`addFeeBuyE6` and `addFeeSellE6` are `uint16` (max 65535, i.e. ~6.5535% in E6 units). [5](#0-4)  When `maxAdminSpreadFeeE6` is set below 65535 (e.g. 10000 = 1%), a pool admin can set per-bin fees to 65535, exceeding the cap by ~6.5×.

**Note on the question's specific proof scenario:** The question states `maxAdminSpreadFeeE6=200000` (20%) and calls with `uint16 max = 65535` (~6.5%). Since 65535 < 200000, the cap is **not** violated in that exact scenario — the proof idea's own condition ("despite `maxAdminSpreadFeeE6 < 65535`") contradicts the 200000 setup. The real exploit requires `maxAdminSpreadFeeE6 < 65535`, e.g. the owner sets the cap to 10000 (1%) and the pool admin then calls with 65535.

### Impact Explanation

Every swap routed through the affected bin pays the uncapped additional fee. The excess fee is extracted from trader principal on each swap. This is a direct, per-swap loss of trader funds and constitutes an admin-boundary break: the pool admin exceeds the protocol-enforced cap.

### Likelihood Explanation

The pool admin is a semi-trusted role. The protocol explicitly caps admin fees via `maxAdminSpreadFeeE6` to bound the admin's power. The missing check in `setPoolBinAdditionalFees` is a straightforward one-call bypass available to any pool admin whenever `maxAdminSpreadFeeE6 < 65535`.

### Recommendation

Add the same cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [2](#0-1) 

### Proof of Concept

1. Owner calls `setFeeCaps(..., maxAdminSpreadFeeE6=10000, ...)` (1% cap).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. No revert occurs; `BinState.addFeeBuyE6 == 65535` despite `maxAdminSpreadFeeE6 == 10000`.
4. Every subsequent swap through bin 0 pays ~6.5535% additional fee instead of the capped 1%, with the excess extracted from trader principal.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L470-472)
```text
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/types/PoolStorage.sol (L22-24)
```text
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
```
