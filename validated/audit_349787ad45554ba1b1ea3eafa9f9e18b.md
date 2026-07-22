After a thorough investigation of the Metric OMM factory, deployer, admin, fee, provider-change, pause, and extension-config code, here is my analysis:

**Invariant mapped from the external bug:** A token-type routing decision based on an address comparison incorrectly sends one asset class through a path designed for a different asset class, causing wrong-asset transfer or transaction failure.

**Paths examined:**

1. **`_validatePoolParameters` / `_validatePriceProvider`** — Token ordering is not enforced (`token0 < token1`), but `_validatePriceProvider` requires `priceProvider.token0() == pool.token0` and `priceProvider.token1() == pool.token1`, so pool and oracle are always consistent. No misrouting. [1](#0-0) 

2. **`collectPoolFees` (permissionless)** — No registry check, but `poolFeeConfig[unregistered]` returns all-zeros, and `collectFees` has an early-return guard `if (spreadSumE6 == 0 && notionalSumE8 == 0) return`. No fund loss path. [2](#0-1) 

3. **`collectFees` fee-split math** — Spread fees are computed on `balance - binTotals - notionalFees` (spread-only surplus), then notional fees are added separately. Total payout ≤ `balance - binTotals`. The test `test_collectProtocolFees_math_overallocates_whenSp

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L541-546)
```text
  function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1) {
      revert PriceProviderTokenMismatch();
    }
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L377-380)
```text
      if (spreadSumE6 == 0 && notionalSumE8 == 0) {
        return;
      }
    }
```
