The key facts are now clear. Let me verify the exact swap fee computation path to confirm the uncapped per-bin fee reaches traders.

The evidence is conclusive. Here is the full analysis:

---

### Title
Uncapped Per-Bin Additional Fees Allow Pool Admin to Bypass `maxAdminSpreadFeeE6` — (`metric-core/contracts/MetricOmmPoolFactory.sol`, `metric-core/contracts/MetricOmmPool.sol`)

### Summary

`setPoolBinAdditionalFees` in the factory and `setBinAdditionalFees` in the pool accept any `uint16` value for `addFeeBuyE6` / `addFeeSellE6` with no cap check. The global admin spread fee path (`setPoolAdminFees`) is capped by `maxAdminSpreadFeeE6`, but the per-bin path has no equivalent guard. Because per-bin fees are added directly to `baseFeeX64` in every swap iteration, the pool admin can charge traders fees far above the documented cap.

### Finding Description

`setPoolAdminFees` enforces the cap:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has no such check — it passes the raw `uint16` values straight through to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` only validates the bin index, not the fee magnitude:

```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

These stored values are applied unconditionally in all four swap paths:

```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

`uint16` max is 65535; in E6 units that is **6.5535%** added on top of the oracle-derived base fee per bin. The hard cap `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) governs only the global spread fee, not per-bin fees. [8](#0-7) 

### Impact Explanation

Every swap that crosses the affected bin pays `baseFeeX64 + 6.5535%` regardless of what `maxAdminSpreadFeeE6` is configured to. The excess fee is extracted from the trader's input and retained in the pool as LP surplus (collectible by the pool admin via `collectPoolFees`). This is a direct, per-swap loss of trader principal that scales with volume and can be triggered immediately with no timelock.

### Likelihood Explanation

The pool admin role is semi-trusted and the call requires no special privilege beyond holding `poolAdmin[pool]`. There is no timelock on `setPoolBinAdditionalFees`. The admin can set the fee to `uint16` max at any time, including front-running a large swap.

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the one in `setPoolAdminFees`:

```solidity
if (uint256(addFeeBuyE6) + uint256(addFeeSellE6) > maxAdminSpreadFeeE6)
    revert AdminFeeTooHigh();
```

Or introduce a dedicated `maxAdminBinFeeE6` cap enforced at the factory level before forwarding to the pool.

### Proof of Concept

1. Deploy a pool with `maxAdminSpreadFeeE6 = 5000` (0.5%).
2. As pool admin, call `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. Execute a swap through bin 0.
4. Observe the effective fee applied to the swap is `baseFeeX64 + 6.5535%`, far exceeding the 0.5% cap.
5. Confirm `setPoolAdminFees(pool, 65535, 0)` would revert with `AdminFeeTooHigh`, proving the bypass is exclusive to the per-bin path.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L464-473)
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
