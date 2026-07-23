The claim is valid. Here is the analysis:

**Key facts confirmed from the code:**

1. `setPoolBinAdditionalFees` in the factory passes `addFeeBuyE6`/`addFeeSellE6` directly to the pool with **no cap check** — only `onlyPoolAdmin` access control. [1](#0-0) 

2. `setBinAdditionalFees` on the pool validates only the bin index range, **not the fee values**. [2](#0-1) 

3. The global spread fee (`setPoolAdminFees`) IS capped by `maxAdminSpreadFeeE6` (hard ceiling `HARD_MAX_SPREAD_FEE_E6 = 200_000` E6 = 20%). [3](#0-2) [4](#0-3) 

4. In the swap loop, the per-bin additional fee is added directly on top of `baseFeeX64` with no clamp: [5](#0-4) [6](#0-5) 

5. The contest scope explicitly lists `setBinAdditionalFees` as an admin-boundary check point: *"pool admin is semi-trusted only inside caps and timelocks; look for bypasses in `setPoolFees`, `setBinAdditionalFees`..."*

**The admin-boundary break:** The global spread fee is capped at 20% (200,000 E6). The per-bin additional fee is `uint16`, max 65,535 E6 = **6.5535%**, with zero cap enforcement. A pool admin can set this on any bin at any time with no timelock, causing traders routing through that bin to pay up to 6.5535% additional fee on top of the already-capped global spread — exceeding the 20% hard ceiling by design.

---

### Title
Pool admin can set per-bin additional fees to `uint16` max with no cap, bypassing the global spread fee ceiling and causing excess trader losses — (`metric-core/contracts/MetricOmmPoolFactory.sol`, `metric-core/contracts/MetricOmmPool.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` enforces no upper bound on `addFeeBuyE6`/`addFeeSellE6`, while the analogous global spread fee path (`setPoolAdminFees`) is bounded by `maxAdminSpreadFeeE6` (hard max 20%). A pool admin can set per-bin additional fees to `uint16` max (65,535 E6 = 6.5535%) on any bin, bypassing the fee cap system and extracting excess fees from traders.

### Finding Description
`MetricOmmPoolFactory.setPoolBinAdditionalFees` (lines 450–457) forwards `addFeeBuyE6` and `addFeeSellE6` directly to `MetricOmmPool.setBinAdditionalFees` (lines 464–474) after only checking `onlyPoolAdmin`. No cap is applied. The pool's `setBinAdditionalFees` only validates the bin index range.

During a swap, the effective fee for a bin is computed as:

```
totalFeeX64 = baseFeeX64 + mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

With `addFeeBuyE6 = 65535`, the additional fee is 6.5535% on top of the oracle-derived base spread. The global spread fee is separately capped at 20% (`HARD_MAX_SPREAD_FEE_E6 = 200_000`), but the per-bin additional fee has no corresponding cap, so the total effective fee for a bin can exceed 26.5535%.

The per-bin additional fee accumulates as spread surplus and is collected by the admin and protocol via `collectFees`. There is no timelock on `setPoolBinAdditionalFees`.

### Impact Explanation
Traders executing swaps through a bin with `addFeeBuyE6 = 65535` pay 6.5535% additional fee beyond the disclosed global spread fee. This is a direct loss of trader principal. The pool admin can apply this to any bin at any time without notice or timelock, and the excess fee flows to the admin's fee destination.

### Likelihood Explanation
The pool admin role is semi-trusted and is explicitly in scope for admin-boundary checks. The action requires only `poolAdmin` access — no timelock, no protocol approval. Any pool admin (including one acting adversarially or one whose key is compromised) can trigger this immediately.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. Introduce a factory-level `maxBinAdditionalFeeE6` constant or configurable cap, and revert if `addFeeBuyE6 > maxBinAdditionalFeeE6 || addFeeSellE6 > maxBinAdditionalFeeE6`. Alternatively, enforce that `globalSpreadFeeE6 + addFeeBuyE6 <= HARD_MAX_SPREAD_FEE_E6`.

### Proof of Concept
1. Deploy pool with `adminSpreadFeeE6 = 0` (global spread fee = oracle spread only).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. `_binStates[0].addFeeBuyE6 = 65535` is stored with no revert.
4. Trader calls `swap(zeroForOne=true, ...)` routing through bin 0.
5. Swap uses `baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)` as total fee.
6. Assert trader pays 6.5535% additional fee; compare to expected fee with `addFeeBuyE6 = 0`.
7. Difference is direct loss of trader principal, exceeding the 20% global hard cap when combined with a non-zero global spread fee.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1088-1088)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
```
