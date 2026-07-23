The code evidence is conclusive. Let me trace the full path.

**`setPoolBinAdditionalFees` in the factory (lines 450–457):** [1](#0-0) 

No cap check whatsoever — it passes `addFeeBuyE6` and `addFeeSellE6` directly to the pool.

**Compare to `setPoolAdminFees` (lines 414–415):** [2](#0-1) 

That function explicitly enforces `maxAdminSpreadFeeE6`. The asymmetry is clear.

**`setBinAdditionalFees` on the pool (lines 464–474):** [3](#0-2) 

Only checks bin index range — no fee magnitude check.

**Per-bin fees are directly applied in every swap path (e.g., line 910, 999, 1177):** [4](#0-3) 

The `addFeeBuyE6` / `addFeeSellE6` values are added to `baseFeeX64` unconditionally, affecting every swap through that bin.

---

### Title
Pool admin bypasses `maxAdminSpreadFeeE6` cap via uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `uint16 addFeeBuyE6` / `addFeeSellE6` directly to `MetricOmmPool.setBinAdditionalFees` with no check against `maxAdminSpreadFeeE6`. The factory's cap system is entirely bypassed for per-bin fees.

### Finding Description
The factory enforces `maxAdminSpreadFeeE6` (itself bounded by `HARD_MAX_SPREAD_FEE_E6 = 200_000`) for the global admin spread fee via `setPoolAdminFees`. However, `setPoolBinAdditionalFees` — also callable by the pool admin — performs no analogous check:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
    // ← no: if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
}
```

A pool admin can call this with `addFeeBuyE6 = 65535` (uint16 max = 6.5535%) on any bin, regardless of what `maxAdminSpreadFeeE6` is configured to. If the factory owner has set `maxAdminSpreadFeeE6 = 1000` (0.1%), the admin can still impose a 6.5535% per-bin additional fee — 65× the intended ceiling.

The per-bin fee is applied additively in every swap through that bin:
```solidity
// MetricOmmPool.sol:910, 999, 1177
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

### Impact Explanation
Traders swapping through the affected bin pay up to 6.5535% additional spread fee on top of the base spread, regardless of the factory-configured admin fee cap. This is a direct loss of trader principal (excess fee extracted from swap output/input). The extra fee accrues to LPs in that bin, not to the admin directly, but the admin can be an LP and self-deal, or simply harm traders.

### Likelihood Explanation
Any pool admin can execute this in a single transaction with no preconditions beyond holding the `poolAdmin` role. The factory owner's cap configuration is rendered meaningless for per-bin fees. The attack is trivially repeatable across all bins.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` mirroring the one in `setPoolAdminFees`:

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
1. Factory owner sets `maxAdminSpreadFeeE6 = 1_000` (0.1%) via `setFeeCaps`.
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — succeeds with no revert.
3. A trader swaps through bin 0; the effective fee is `baseFee + 6.5535%`, far exceeding the 0.1% cap.
4. Assert: `BinState.addFeeBuyE6 == 65535` and effective fee > `maxAdminSpreadFeeE6`.

> **Note on the question's proof setup:** The question uses `maxAdminSpreadFeeE6 = 200_000` (20%), which is the hard maximum. In that specific setup, `65535 < 200_000` so no cap is actually exceeded numerically. The bypass is demonstrated when `maxAdminSpreadFeeE6` is set to any value below 65535 (e.g., 1_000 or 10_000), which is the realistic production scenario where the factory owner intends to limit admin fees to a modest level.

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
