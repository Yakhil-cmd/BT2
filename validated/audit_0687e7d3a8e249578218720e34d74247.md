The code confirms the claim. Here is the full analysis:

**Key facts established:**

1. `MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6`/`addFeeSellE6` straight through to the pool with zero cap validation: [1](#0-0) 

2. `MetricOmmPool.setBinAdditionalFees` only validates the bin index, then writes the values directly: [2](#0-1) 

3. By contrast, `setPoolAdminFees` enforces explicit factory caps before writing: [3](#0-2) 

4. The bin additional fees are added directly to `baseFeeX64` in every swap path: [4](#0-3) [5](#0-4) 

5. The factory's hard cap system (`HARD_MAX_SPREAD_FEE_E6 = 200_000`, `maxAdminSpreadFeeE6`) governs `setPoolAdminFees` but is entirely absent from the bin additional fee path: [6](#0-5) 

**Scope rule check:** The scope rules explicitly designate the pool admin as "semi-trusted only inside caps and timelocks" and call out `setBinAdditionalFees` as an admin path to check for cap bypasses. The pool admin is not the factory owner; they are a distinct, semi-trusted role. The absence of any cap on `addFeeBuyE6`/`addFeeSellE6` while `setPoolAdminFees` has explicit caps is an admin-boundary break — the pool admin can exceed the fee cap system through this path.

---

### Title
Pool admin can set per-bin additional fees to uint16 max (~6.55%) with no factory-enforced cap, extracting excess value from traders — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` to the pool without any cap check. The analogous `setPoolAdminFees` enforces `maxAdminSpreadFeeE6` / `maxAdminNotionalFeeE8`, but no equivalent guard exists for per-bin additional fees. A pool admin can set either value to `type(uint16).max` (65535 ≈ 6.55%) and the factory will accept it unconditionally.

### Finding Description
`MetricOmmPoolFactory.setPoolBinAdditionalFees` (lines 450–457) calls `IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6)` with no validation of the fee values. `MetricOmmPool.setBinAdditionalFees` (lines 464–474) only validates the bin index and writes `s.addFeeBuyE6 = addFeeBuyE6` and `s.addFeeSellE6 = addFeeSellE6` directly. The factory's cap system (`maxAdminSpreadFeeE6`, `HARD_MAX_SPREAD_FEE_E6 = 200_000`) is never consulted. The per-bin additional fees are added to `baseFeeX64` in all four swap paths (`_swapToken1ForToken0SpecifiedOutput`, `_swapToken1ForToken0SpecifiedInput`, `_swapToken0ForToken1SpecifiedOutput`, `_swapToken0ForToken1SpecifiedInput`) before computing the ask/bid price, so they directly inflate the cost paid by traders.

### Impact Explanation
A pool admin who sets `addFeeBuyE6 = 65535` and `addFeeSellE6 = 65535` on any active bin causes every trader swapping through that bin to pay an additional ~6.55% fee on top of the configured spread and notional fees. This fee is taken from the trader's input token and retained in the pool (as LP fee), constituting a direct, quantifiable loss of trader principal. The impact is immediate and affects all swaps through the targeted bin until the admin resets the value.

### Likelihood Explanation
The pool admin is a semi-trusted role that can be transferred via a two-step process. Any compromise or malicious assignment of the pool admin key enables this attack with a single transaction. No timelock, no protocol approval, and no cap check stands in the way. The asymmetry with `setPoolAdminFees` (which does enforce caps) makes this a clear design gap rather than an intentional design choice.

### Recommendation
Add a factory-level cap check in `setPoolBinAdditionalFees` analogous to the check in `setPoolAdminFees`. Either reuse `maxAdminSpreadFeeE6` as the ceiling for per-bin additional fees, or introduce a dedicated `maxBinAdditionalFeeE6` storage variable with a corresponding setter guarded by `onlyOwner`. The check should revert with `AdminFeeTooHigh()` (or a new `BinAdditionalFeeTooHigh()` error) if either `addFeeBuyE6` or `addFeeSellE6` exceeds the cap.

```solidity
// In MetricOmmPoolFactory.setPoolBinAdditionalFees:
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
```

### Proof of Concept
1. Deploy factory and pool with default parameters.
2. As pool admin, call `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)`.
3. Observe that the call succeeds and `_binStates[0].addFeeBuyE6 == 65535`.
4. Execute a swap through bin 0; assert the trader receives materially less than the oracle price permits (the effective ask price is inflated by ~6.55% above the base spread).
5. Confirm no revert occurs at any point in the factory or pool — the cap system is entirely bypassed.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```

**File:** metric-core/contracts/MetricOmmPool.sol (L999-999)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```
