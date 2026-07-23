The code evidence is conclusive. Let me trace the full path.

**`setPoolBinAdditionalFees` — no cap check:** [1](#0-0) 

**`setPoolAdminFees` — cap IS enforced:** [2](#0-1) 

**`setBinAdditionalFees` on pool — no cap check either:** [3](#0-2) 

**Bin additional fees are directly applied in every swap path:** [4](#0-3) [5](#0-4) [6](#0-5) 

The Smart Audit Pivots explicitly flag `setBinAdditionalFees` as a bypass surface. The asymmetry is real and the swap impact is direct. This is a valid finding.

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` (both `uint16`, max 65535) directly to the pool with no validation against `maxAdminSpreadFeeE6`. The parallel function `setPoolAdminFees` enforces the cap; `setPoolBinAdditionalFees` does not. Because bin additional fees are added to `baseFeeX64` inside every swap branch, a pool admin can impose up to 6.5535% additional fee per bin on traders regardless of what the factory owner configured as the admin fee ceiling.

### Finding Description
`MetricOmmPoolFactory.setPoolAdminFees` correctly gates the admin spread fee:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

`MetricOmmPoolFactory.setPoolBinAdditionalFees` has no equivalent guard:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

`MetricOmmPool.setBinAdditionalFees` also has no cap check — it only validates the bin index range. The stored `addFeeBuyE6`/`addFeeSellE6` values are then unconditionally added to `baseFeeX64` in all four swap branches (`buyToken0SpecifiedOut`, `buyToken0SpecifiedIn`, `buyToken1SpecifiedOut`, `buyToken1SpecifiedIn`).

A pool admin can therefore call `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` and set a 6.5535% per-bin additional fee even when `maxAdminSpreadFeeE6` is configured to, say, 1% (10,000 E6).

### Impact Explanation
Every trader whose swap routes through an affected bin pays `baseFee + 6.5535%` instead of the capped maximum. The excess fee accrues to LPs (not the admin directly), but the trader suffers direct principal loss above the protocol-configured ceiling. With up to 256 bins configurable, the admin can apply this to every bin in the pool. This is a direct, quantifiable loss to traders that exceeds the Sherlock Medium threshold.

### Likelihood Explanation
The pool admin is a semi-trusted role whose power is explicitly bounded by `maxAdminSpreadFeeE6`. The bypass requires only a single transaction from the pool admin — no special conditions, no oracle manipulation, no token quirks. Any pool whose admin is compromised or acts adversarially triggers this immediately.

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

Alternatively, enforce a combined cap (global admin spread + bin additional fee) if the intent is to bound total effective fee.

### Proof of Concept
```solidity
// Foundry test sketch
function test_binFeeBypassesCap() public {
    address pool = _createPool();
    // Factory owner sets admin spread cap to 1%
    factory.setFeeCaps(200_000, 10_000, 1_000_000, 1_000_000);

    // Pool admin sets bin additional fee to uint16 max = 6.5535%
    vm.prank(admin);
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535); // succeeds — no revert

    // Simulate swap through bin 0; effective fee = baseFee + 6.5535%
    // Assert trader receives less than oracle price minus 1% cap allows
}
```

The call succeeds because neither `setPoolBinAdditionalFees` nor `setBinAdditionalFees` checks `maxAdminSpreadFeeE6`. [1](#0-0) [3](#0-2)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1177)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
