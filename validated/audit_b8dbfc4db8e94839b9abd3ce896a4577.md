The code evidence is conclusive. Let me trace the full path before rendering a verdict.

**`setPoolBinAdditionalFees` — no cap check:** [1](#0-0) 

**`setPoolAdminFees` — has cap check:** [2](#0-1) 

**`setBinAdditionalFees` on pool — writes directly, no cap:** [3](#0-2) 

**Bin fee applied in swap math (buy direction):** [4](#0-3) 

**Bin fee applied in swap math (sell direction):** [5](#0-4) 

**Factory hard cap constant:** [6](#0-5) 

---

### Title
Pool admin bypasses `maxAdminSpreadFeeE6` cap via uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` directly to `pool.setBinAdditionalFees` with no validation against `maxAdminSpreadFeeE6`. The parallel path `setPoolAdminFees` enforces `if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh()`, but the bin-level path has no equivalent guard. A pool admin can therefore set per-bin fees to `uint16.max = 65535` (6.5535% in E6 units) regardless of what `maxAdminSpreadFeeE6` is set to, including zero.

### Finding Description

`MetricOmmPoolFactory.setPoolAdminFees` enforces the factory cap:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

`MetricOmmPoolFactory.setPoolBinAdditionalFees` has no such check:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` writes the values directly to `BinState.addFeeBuyE6` / `BinState.addFeeSellE6`. During every swap, the pool computes the effective per-bin fee as:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

This means the bin additional fee is added on top of the base spread fee and is applied to every swap touching that bin. With `addFeeBuyE6 = 65535`, the additional fee is 6.5535%, which is applied regardless of the factory's `maxAdminSpreadFeeE6` setting.

The factory owner can set `maxAdminSpreadFeeE6 = 0` to prevent any admin spread fee extraction, but the pool admin can still extract up to 6.5535% per bin via this path. The two fee mechanisms are architecturally parallel but only one is capped.

### Impact Explanation

Traders swapping through any bin where the pool admin has set `addFeeBuyE6` or `addFeeSellE6` to an elevated value receive less output than the factory-enforced cap permits. With `addFeeBuyE6 = 65535` and `maxAdminSpreadFeeE6 = 0`, a trader executing a swap through that bin pays 6.5535% more than the factory cap allows. This is direct loss of swap output for every affected trader, proportional to swap size and the number of bins traversed with elevated fees. The pool admin can apply this to all bins simultaneously.

### Likelihood Explanation

The pool admin role is semi-trusted and is expected to be bounded by factory caps. The factory owner may set `maxAdminSpreadFeeE6` to a low value (including zero) to protect users of a pool. Any pool admin who is adversarial or compromised can immediately call `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535` on every bin without any timelock, without any cap check, and without any factory-owner override path to prevent it. The action is a single transaction.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinFeeE6` cap if bin fees are intended to have a separate ceiling.

### Proof of Concept

1. Deploy factory with `maxAdminSpreadFeeE6 = 0` (factory owner wants zero admin spread fees).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — succeeds with no revert.
3. Trader calls `pool.swap(...)` routing through bin 0.
4. Swap math computes effective fee as `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` — an additional 6.5535% fee is applied.
5. Trader receives ~6.5535% less output than the oracle-permitted price allows, despite `maxAdminSpreadFeeE6 = 0`.
6. The factory cap invariant is violated: pool admin extracted fees above the factory-enforced zero cap.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L43-45)
```text
  /// @dev Owner `setFeeCaps` values cannot exceed these (spread: 1e6 = 100%; notional: 1e8 = 100%)
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-415)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L906-915)
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
          );
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1084-1093)
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
          );
```
