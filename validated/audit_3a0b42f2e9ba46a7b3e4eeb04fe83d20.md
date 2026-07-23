### Title
Pool Admin Bypasses Hard Fee Cap via Uncapped Per-Bin Additional Fees in `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
The factory enforces a hard spread-fee ceiling of 20% (`HARD_MAX_SPREAD_FEE_E6 = 200_000`) on every global-fee setter, but the per-bin additional-fee path (`setPoolBinAdditionalFees` → `setBinAdditionalFees`) accepts raw `uint16` values with no cap check. A pool admin can write `addFeeBuyE6` / `addFeeSellE6` up to 65 535 (≈ 6.55 % in E6 units) for any bin, and those values are added directly to the base fee inside every swap through that bin, pushing the effective per-bin fee above the hard ceiling.

### Finding Description
`MetricOmmPoolFactory` applies `HARD_MAX_SPREAD_FEE_E6 = 200_000` consistently to every global-fee mutator:

- `setFeeCaps` — rejects caps above the hard limit [1](#0-0) 
- `setPoolAdminFees` — rejects `newAdminSpreadFeeE6 > maxAdminSpreadFeeE6` [2](#0-1) 
- `setPoolProtocolFee` — rejects `newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6` [3](#0-2) 

However, `setPoolBinAdditionalFees` passes `addFeeBuyE6` and `addFeeSellE6` straight through to the pool with no validation at all:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [4](#0-3) 

`MetricOmmPool.setBinAdditionalFees` only checks the bin-index range, not the fee magnitudes:

```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    ...
}
``` [5](#0-4) 

During every swap the per-bin fee is added directly to `baseFeeX64` before the swap-math price calculation:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [6](#0-5) [7](#0-6) 

The same pattern applies to `addFeeSellE6` on the sell side: [8](#0-7) 

The same gap exists at pool-creation time: `_unpackAndValidateBinStates` unpacks only `length` from each packed bin word and silently discards the buy/sell fee fields:

```solidity
(uint256 length,,) = binData.unpack();
``` [9](#0-8) 

### Impact Explanation
A pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)`. Every swap routed through bin 0 now pays an additional ≈ 6.55 % fee on top of the global spread fee (itself up to 20 %). The effective per-bin fee ceiling becomes ≈ 26.55 %, exceeding the hard cap the factory is designed to enforce. Traders receive less output than the documented maximum fee permits; the surplus accrues as spread and is split between admin and protocol on the next `collectFees` call, constituting a direct extraction of trader value above the protocol's stated cap.

### Likelihood Explanation
The pool admin role is semi-trusted and is explicitly expected to operate only within the caps enforced by the factory. The `setPoolBinAdditionalFees` path is a normal post-deployment admin action, callable at any time without a timelock. Any pool admin — including one who was legitimate at deployment but later becomes adversarial — can trigger this unilaterally.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` (and symmetrically in `setBinAdditionalFees` on the pool, or enforce it solely at the factory layer):

```solidity
// In MetricOmmPoolFactory.setPoolBinAdditionalFees:
if (uint256(addFeeBuyE6) + uint256(addFeeSellE6) > HARD_MAX_SPREAD_FEE_E6)
    revert AdminFeeTooHigh();
```

Also validate `addFeeBuyE6` / `addFeeSellE6` inside `_unpackAndValidateBinStates` during `createPool` so the same limit is enforced at deployment time.

### Proof of Concept
1. Deploy a pool with `adminSpreadFeeE6 = 200_000` (20 % — at the hard cap).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — succeeds with no revert.
3. A trader calls `pool.swap(...)` routing through bin 0.
4. Inside `_swapToken1ForToken0SpecifiedInput`, the effective fee passed to `SwapMath.buyToken0InBinSpecifiedIn` is `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)`, i.e., the oracle-spread fee plus ≈ 6.55 % extra.
5. The trader receives materially less token0 than the 20 % hard-cap scenario would allow; the difference is retained in the pool as spread surplus and collected by admin/protocol via `collectPoolFees`.
6. No factory guard reverts at any step.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L290-294)
```text
    if (
      newMaxProtocolSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6 || newMaxAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6
        || newMaxProtocolNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8 || newMaxAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8
    ) {
      revert FeeCapsExceedHardLimit();
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L324-325)
```text
    if (newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (newProtocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
```

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L581-581)
```text
        (uint256 length,,) = binData.unpack();
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
