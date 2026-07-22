### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFees` enforces `maxAdminSpreadFeeE6` on the global spread fee component, but `setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with **no cap check**. A pool admin can set per-bin additional fees to `uint16.max` (65535 E6 = 6.5535%) on any bin, including boundary bins, bypassing the protocol-enforced admin fee ceiling entirely.

---

### Finding Description

`setPoolAdminFees` in `MetricOmmPoolFactory` correctly enforces the cap:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` has no such check — it forwards the caller-supplied values directly:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`setBinAdditionalFees` on the pool only validates the bin index range, not the fee magnitude:

```solidity
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

These per-bin fees are then added directly to `baseFeeX64` in every swap path:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The `BinState` fields are `uint16`, so the maximum settable value is 65535 E6 = **6.5535%** additional fee per bin, regardless of what `maxAdminSpreadFeeE6` is configured to. [8](#0-7) 

**Note on the "boundary bin" framing**: The question frames this as specific to `LOWEST_BIN`/`HIGHEST_BIN`. That framing is a red herring — the missing cap applies to every bin index in `[LOWEST_BIN, HIGHEST_BIN]`, not just boundary bins. The boundary check in `setBinAdditionalFees` correctly permits boundary bins as valid targets; the vulnerability is the absent fee-magnitude cap, which is universal across all bins.

---

### Impact Explanation

A pool admin can set `addFeeBuyE6 = 65535` or `addFeeSellE6 = 65535` on any bin. Every swap routed through that bin pays up to 6.5535% additional fee on top of the global spread fee, regardless of the `maxAdminSpreadFeeE6` cap. For a pool with `maxAdminSpreadFeeE6 = 1000` (0.1%), the admin can charge 65× the protocol-permitted maximum. Traders lose principal directly proportional to the excess fee on every affected swap. This is a direct, quantifiable loss of user funds above Sherlock thresholds.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that is explicitly expected to operate only within protocol-enforced caps. The entrypoint is a normal pool-admin action requiring only `poolAdmin[pool] == msg.sender`. No timelock, no additional role, no special setup is needed beyond being the pool admin. The bypass is a single call.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the cap inside `setBinAdditionalFees` on the pool by passing `maxAdminSpreadFeeE6` as a parameter, or store a per-pool cap accessible to the pool contract.

---

### Proof of Concept

1. Deploy a pool with `maxAdminSpreadFeeE6 = 1000` (0.1%).
2. As pool admin, call `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. Observe: no revert. `_binStates[0].addFeeBuyE6 == 65535`, `addFeeSellE6 == 65535`.
4. Perform a swap through bin 0. The effective fee applied is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — 6.5535% additional, far exceeding the 0.1% cap.
5. Assert: fee charged to trader exceeds `maxAdminSpreadFeeE6` by 65×.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/types/PoolStorage.sol (L19-25)
```text
struct BinState {
  uint104 token0BalanceScaled;
  uint104 token1BalanceScaled;
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
}
```
