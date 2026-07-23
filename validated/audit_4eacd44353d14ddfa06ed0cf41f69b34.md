### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` - (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no validation against `maxAdminSpreadFeeE6`, allowing the pool admin to impose per-bin spread fees that exceed the factory-enforced cap. Every swap through the affected bin pays the uncapped additional fee on top of the base spread, producing ask/bid prices that exceed what the oracle-anchored cap permits.

### Finding Description

The factory maintains a two-level fee cap system. The factory owner sets `maxAdminSpreadFeeE6` (and `maxAdminNotionalFeeE8`) via `setFeeCaps`, and `setPoolAdminFees` enforces those caps before updating the pool's aggregate `spreadFeeE6`:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

However, `setPoolBinAdditionalFees` performs no analogous check:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` stores the values without any cap check either:

```solidity
// MetricOmmPool.sol L464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
```

During every swap, the bin additional fee is added directly on top of `baseFeeX64` (which is derived from the oracle spread):

```solidity
// MetricOmmPool.sol L999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

The same pattern appears for all four swap directions (lines 910, 999, 1088, and the sell-side equivalent). The `uint16` type allows values up to 65 535 E6 ≈ 6.55 %, which can be set regardless of what `maxAdminSpreadFeeE6` is — even if the factory owner has set it to zero.

### Impact Explanation

Every swap through the affected bin pays `spreadFeeE6 + addFeeBuyE6` (or `addFeeSellE6`) as the effective spread. The pool admin can set `addFeeBuyE6 = type(uint16).max = 65535` (≈ 6.55 %) on any bin, bypassing the `maxAdminSpreadFeeE6` cap entirely. Traders receive worse execution prices than the oracle-anchored cap permits — a direct loss of swap output to the trader and a corresponding gain to the LP/admin. This is an admin-boundary break: the pool admin exceeds the cap the factory owner intended to enforce.

### Likelihood Explanation

The pool admin is a valid, semi-trusted actor who can call `setPoolBinAdditionalFees` at any time with no timelock. The call requires only `onlyPoolAdmin(pool)`. There is no off-chain or on-chain guard that prevents the admin from supplying `addFeeBuyE6 = type(uint16).max`. The factory owner's `setFeeCaps` action has no retroactive effect on bin additional fees.

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

Alternatively, enforce the cap at the pool level inside `setBinAdditionalFees` by reading the factory's `maxAdminSpreadFeeE6`. Also audit initial bin data passed through `createPool` → `_unpackAndValidateBinStates` for the same missing cap on `buyFee`/`sellFee` fields.

### Proof of Concept

1. Factory owner deploys factory and sets `maxAdminSpreadFeeE6 = 0` (admin should have zero fee power).
2. Pool admin calls `factory.setPoolAdminFees(pool, 0, 0)` — passes, because 0 ≤ 0.
3. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — passes with no revert.
4. A trader swaps through bin 0. The effective buy fee becomes `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` ≈ `baseFeeX64 + 6.55 %`, far above the intended 0 % admin cap.
5. The trader pays ≈ 6.55 % more than the oracle-anchored cap allows; the excess accrues to the LP bin balance.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L284-299)
```text
  function setFeeCaps(
    uint24 newMaxProtocolSpreadFeeE6,
    uint24 newMaxAdminSpreadFeeE6,
    uint24 newMaxProtocolNotionalFeeE8,
    uint24 newMaxAdminNotionalFeeE8
  ) external override onlyOwner {
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
    }
    maxProtocolSpreadFeeE6 = newMaxProtocolSpreadFeeE6;
    maxAdminSpreadFeeE6 = newMaxAdminSpreadFeeE6;
    maxProtocolNotionalFeeE8 = newMaxProtocolNotionalFeeE8;
    maxAdminNotionalFeeE8 = newMaxAdminNotionalFeeE8;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L413-415)
```text
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L997-1004)
```text
              curPosInBinCache,
              state,
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
              lowerPriceX64,
              upperPriceX64,
              params.priceLimitX64,
              spreadFeeE6
            );
```
