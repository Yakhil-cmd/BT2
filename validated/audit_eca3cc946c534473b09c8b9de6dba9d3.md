The code confirms a real admin-boundary break. Here is the analysis:

**Key code paths:**

`setPoolAdminFees` enforces the cap: [1](#0-0) 

`setPoolBinAdditionalFees` has **no cap check** — it passes values directly through: [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` only validates the bin index, not the fee values: [3](#0-2) 

The uncapped `addFeeBuyE6`/`addFeeSellE6` values are then directly added to the base fee in every swap path: [4](#0-3) [5](#0-4) 

---

### Title
Pool admin bypasses `maxAdminSpreadFeeE6` cap via unchecked `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` and `addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`, while the parallel `setPoolAdminFees` path correctly enforces that cap. A pool admin can set per-bin fees to `uint16` max (65535 ≈ 6.5535%) regardless of the factory-configured cap.

### Finding Description
The factory maintains `maxAdminSpreadFeeE6` as the ceiling on admin-controlled spread fees. `setPoolAdminFees` enforces this with an explicit revert:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

But `setPoolBinAdditionalFees` (the other admin fee-setting path) contains no equivalent guard:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

`MetricOmmPool.setBinAdditionalFees` only checks the bin index range and writes the values unconditionally:

```solidity
// MetricOmmPool.sol:469-472
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
BinState storage s = _binStates[bin];
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
```

During every swap, the stored `addFeeBuyE6`/`addFeeSellE6` is added directly to the base fee passed to `SwapMath`, with no clamping:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

### Impact Explanation
Traders swapping through any bin where the pool admin has set `addFeeBuyE6` or `addFeeSellE6` to an uncapped value pay fees far above the factory-configured admin cap. At `uint16` max (65535), the per-bin additional fee alone is ≈6.5535%, which can be stacked on top of the global spread fee. The excess fee is credited to LP balances in that bin (and ultimately to the admin-controlled fee destination via `collectFees`), constituting a direct extraction of trader principal beyond the protocol-sanctioned limit. This is a direct loss of user funds and an admin-boundary break.

### Likelihood Explanation
The pool admin is a semi-trusted role constrained by factory caps. The bypass requires only a single call to `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535` — no special conditions, no timelock, no co-signer. Any pool whose admin is compromised or malicious can exploit this immediately.

### Recommendation
Add the same cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

### Proof of Concept
```solidity
// Foundry test sketch
function test_binFeeBypassesCap() public {
    // maxAdminSpreadFeeE6 = e.g. 10_000 (1%)
    // pool admin sets bin 0 fees to uint16 max
    vm.prank(poolAdmin);
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Verify storage was written unchecked
    (,,, uint16 buyFee, uint16 sellFee) = PoolStateLibrary._binState(pool, 0);
    assertEq(buyFee, 65535);  // 6.5535% — far above maxAdminSpreadFeeE6
    assertEq(sellFee, 65535);

    // Execute a swap through bin 0 and assert effective fee >> maxAdminSpreadFeeE6
    // trader receives significantly less than oracle price implies
}
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-1003)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1181)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
```
