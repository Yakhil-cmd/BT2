The finding is valid. Here is the analysis:

**Key code facts:**

`setPoolAdminFees` in the factory enforces the cap: [1](#0-0) 

`setPoolBinAdditionalFees` in the factory has **no cap check** — it passes values straight through: [2](#0-1) 

`setBinAdditionalFees` on the pool also has **no cap check** — it stores whatever the factory sends: [3](#0-2) 

The per-bin fee is added directly to the base fee when computing `currBinBuyFeeX64` passed to `SwapMath.buyToken0InBinSpecifiedIn`: [4](#0-3) 

The fee is then applied to inflate the gross input charged to the trader: [5](#0-4) 

---

### Title
Pool admin bypasses `maxAdminSpreadFeeE6` cap via uncapped `setPoolBinAdditionalFees`, overcharging traders on targeted bins — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` enforces only `onlyPoolAdmin` access control but applies **no upper-bound check** on `addFeeBuyE6` / `addFeeSellE6` against `maxAdminSpreadFeeE6`. The parallel function `setPoolAdminFees` correctly gates its inputs with `if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh()`, but that guard is absent from the bin-level path. A pool admin can therefore set per-bin additional fees up to `type(uint16).max = 65535` E6 (≈6.55%) on any bin, regardless of the factory-configured cap.

### Finding Description
The factory stores `maxAdminSpreadFeeE6` (a `uint24`, capped by the owner at ≤ `HARD_MAX_SPREAD_FEE_E6 = 200_000`) to bound how much fee the pool admin may charge. `setPoolAdminFees` respects this cap. `setPoolBinAdditionalFees` does not:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  // ← no cap check against maxAdminSpreadFeeE6
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

`setBinAdditionalFees` on the pool stores the value verbatim. During a swap, the pool computes:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

and passes this as `currBinBuyFeeX64` to `SwapMath.buyToken0InBinSpecifiedIn`, which uses it to compute `grossInputWithBinFeeCeil`. With `addFeeBuyE6 = 65535`, the per-bin effective fee is `spreadFeeE6 (base) + 65535 E6 (bin override)`, far exceeding any cap the owner configured.

### Impact Explanation
Traders executing swaps through the targeted bin pay a grossly inflated input amount. The excess fee accrues to the bin's LP balance (net of the protocol's `spreadFeeE6` share). If the pool admin also holds LP positions in that bin, they directly extract value from traders. Even without LP positions, the overcharge constitutes a direct loss of trader principal above Sherlock thresholds (the admin can set the bin fee to 6.55% on top of the base spread, which can be up to 20%, for a combined effective fee of ~26.55% on a single bin).

### Likelihood Explanation
The pool admin is a semi-trusted role that is explicitly expected to be bounded by caps. The bypass requires only a single call to `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535`. No timelock, no co-signer, no oracle manipulation. Any pool admin can execute this immediately.

### Recommendation
Add the same cap check present in `setPoolAdminFees`:

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
```solidity
// Foundry unit test sketch
function test_binFeeBypassesCap() public {
    address pool = _createPool();

    // Owner sets a tight cap: 1000 E6 = 0.1%
    factory.setFeeCaps(200_000, 1_000, 1_000_000, 1_000_000);

    // Pool admin sets per-bin fee to type(uint16).max = 65535 — no revert
    vm.prank(admin);
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 0);

    // Confirm stored value exceeds maxAdminSpreadFeeE6
    (,,, uint16 addFeeBuyE6,) = PoolStateLibrary._binState(pool, 0);
    assertEq(addFeeBuyE6, 65535);
    assertGt(uint24(addFeeBuyE6), factory.maxAdminSpreadFeeE6()); // 65535 > 1000

    // Execute a swap through bin 0 and assert grossInput >> oracle-permitted amount
    // (swap setup omitted for brevity; the fee charged will include 65535 E6 on top of base)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L994-1004)
```text
          (curPosInBinCache, outToken0AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken0InBinSpecifiedIn(
              binState,
              curPosInBinCache,
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
            );
```

**File:** metric-core/contracts/libraries/SwapMath.sol (L564-574)
```text
      uint256 onePlusBuyFeeX64 = ONE_X64 + currBinBuyFeeX64;

      // Check if we can consume up to maxFinalBinPos directly
      out0Scaled = calculateOutputToken0FromBinPosition(binState.token0BalanceScaled, currBinPos, maxFinalBinPos);

      // Both uint104: avg of two uint104 values ≤ MAX_POS_BIN
      uint256 finalPriceX64 =
        calculatePriceAtBinPosition(lowerPriceX64, upperPriceX64, maxFinalBinPos, Math.Rounding.Ceil);
      uint256 avgPriceX64 = calculateArithmeticMean(startingPriceX64, finalPriceX64);
      uint256 in1WithoutFeeScaled = calculateRequiredToken(out0Scaled, avgPriceX64);
      uint256 totalIn1Scaled = grossInputWithBinFeeCeil(in1WithoutFeeScaled, onePlusBuyFeeX64);
```
