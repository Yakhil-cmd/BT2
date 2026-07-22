The vulnerability is confirmed. Here is the complete analysis:

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Unchecked `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`, allowing the pool admin to store per-bin fees up to `uint16.max` (65 535 E6 = 6.5535%) in `BinState`. Every swap through the affected bin then pays an effective fee that can be orders of magnitude above the factory-enforced admin cap, causing direct loss of swap output to traders.

### Finding Description

`setPoolAdminFees` correctly guards the global admin spread component: [1](#0-0) 

`setPoolBinAdditionalFees` has no equivalent guard: [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` also performs no cap check — it only validates the bin index and writes the raw values: [3](#0-2) 

The stored `addFeeBuyE6` / `addFeeSellE6` are then added directly on top of `baseFeeX64` in every swap path through that bin: [4](#0-3) [5](#0-4) [6](#0-5) 

The same unchecked path is visible in `getSellAndBuyPrices` and the periphery data provider, confirming the per-bin fee is applied uniformly to all swap math: [7](#0-6) 

### Impact Explanation

A pool admin can call `factory.setPoolBinAdditionalFees(pool, bin, 65535, 65535)` with no revert. The `BinState` for that bin stores `addFeeBuyE6 = addFeeSellE6 = 65535`. Every subsequent swap routed through that bin pays an effective spread fee of `baseFee + 6.5535%` instead of the factory-capped maximum. The excess fee is retained in the pool as LP surplus (not collected as protocol or admin fee), meaning traders lose principal on every swap while the factory owner's `maxAdminSpreadFeeE6` invariant is silently violated. This is a direct, per-swap loss of user funds.

### Likelihood Explanation

The pool admin role is semi-trusted and constrained by caps. The cap system (`maxAdminSpreadFeeE6`) is the protocol's explicit guarantee to traders and LPs that admin power is bounded. Any pool admin — including one who turns adversarial after deployment — can exploit this gap immediately with a single transaction, with no timelock or protocol-owner approval required.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool, mirroring the guard in `setPoolAdminFees`:

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
// Foundry integration test sketch
function test_binFeeBypassesCap() public {
    // Factory owner sets a low admin spread cap
    factory.setFeeCaps(
        maxProtocolSpreadFeeE6,
        1000,   // maxAdminSpreadFeeE6 = 0.1%
        maxProtocolNotionalFeeE8,
        maxAdminNotionalFeeE8
    );

    address pool = _createPool(); // adminSpreadFeeE6 = 0 at creation

    // Pool admin sets per-bin fee to uint16.max — no revert
    vm.prank(admin);
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Verify stored value exceeds cap
    (,,, uint16 buyFee, uint16 sellFee) = PoolStateLibrary._binState(pool, 0);
    assertEq(buyFee, 65535);  // 6.5535% >> 0.1% cap
    assertGt(uint256(buyFee), uint256(factory.maxAdminSpreadFeeE6()));

    // Execute a swap through bin 0 and assert effective fee far exceeds cap
    // (swap output will be reduced by ~6.5535% instead of the capped 0.1%)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-544)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);

    uint256 askBeforeNotional = Math.mulDiv(marginalPriceX64, ONE_X64 + buyFeeX64, ONE_X64, Math.Rounding.Ceil);
    uint256 bidAfterSpread = Math.mulDiv(marginalPriceX64, ONE_X64, ONE_X64 + sellFeeX64, Math.Rounding.Floor);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L906-914)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken0InBinSpecifiedOut(
            binState,
            curPosInBinCache,
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1084-1092)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken1InBinSpecifiedOut(
            binState,
            curPosInBinCache,
            state,
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
            lowerPriceX64,
            upperPriceX64,
            params.priceLimitX64,
            spreadFeeE6
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1172-1182)
```text
          (curPosInBinCache, outToken1AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken1InBinSpecifiedIn(
              binState,
              curPosInBinCache,
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
            );
```
