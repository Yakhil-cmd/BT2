I need to read the `ValidateExtensionsConfig` and `SwapMath` libraries, and check the `SECURITY.md` for context before finalizing.

Based on my thorough review of the factory, pool, deployer, and extension-calling code, here is my analysis:

**Invariant classification**: The external bug maps to *admin-boundary break* — attacker-controlled (or semi-trusted-admin-controlled) input is accepted without validation against the factory owner's caps, allowing the admin to exceed intended limits.

**Trace through the code**:

- `setPoolAdminFees` validates `newAdminSpreadFeeE6 <= maxAdminSpreadFeeE6` and `newAdminNotionalFeeE8 <= maxAdminNotionalFeeE8` before updating fees. [1](#0-0) 
- `setPoolBinAdditionalFees` passes `addFeeBuyE6` and `addFeeSellE6` **directly** to the pool with **no cap validation** whatsoever. [2](#0-1) 
- The pool's `setBinAdditionalFees` only checks the bin index range, not the fee values. [3](#0-2) 
- In every swap path, `addFeeBuyE6`/`addFeeSellE6` are added directly on top of the oracle-derived `baseFeeX64`, increasing the effective fee charged to traders. [4](#0-3) 
- `uint16` allows values up to 65 535, i.e. 6.5535 % in E6 units — uncapped by any factory-owner-controlled parameter.

**Existing guards**: `maxAdminSpreadFeeE6` and `maxAdminNotionalFeeE8` guard the spread/notional fee paths but there is no analogous guard for bin additional fees. The asymmetry is the root cause.

**Rejection check**: The pool admin is semi-trusted *only inside caps*. The factory owner can set `maxAdminSpreadFeeE6 = 0` to prevent any admin spread fee, yet the pool admin retains the ability to impose up to 6.5535 % per-bin fees through the uncapped path. This is a cap bypass, not a trusted-admin action within caps.

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped Bin Additional Fees — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`setPoolBinAdditionalFees` forwards `addFeeBuyE6`/`addFeeSellE6` to the pool without validating them against any factory-owner-controlled cap, allowing the pool admin to charge per-bin fees up to 6.5535 % regardless of the `maxAdminSpreadFeeE6` limit the factory owner has set.

### Finding Description
The factory enforces two admin fee caps:

```solidity
// MetricOmmPoolFactory.sol L414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

These caps are enforced in `setPoolAdminFees`. However, the parallel admin entry-point `setPoolBinAdditionalFees` performs no such check:

```solidity
// MetricOmmPoolFactory.sol L450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` only validates the bin index:

```solidity
// MetricOmmPool.sol L469
if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
```

In every swap path the bin additional fee is added directly to the oracle-derived base fee before computing the trade:

```solidity
// MetricOmmPool.sol L999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
```

`uint16` permits values up to 65 535 (6.5535 % in E6 units). No factory-owner parameter constrains this.

### Impact Explanation
Traders swapping through a bin with `addFeeBuyE6 = 65535` pay up to 6.5535 % in additional fees on top of the oracle spread. This is a direct loss of user principal on every swap through that bin. The factory owner's ability to set `maxAdminSpreadFeeE6 = 0` is rendered meaningless for bins where the pool admin has set high additional fees. The pool admin (or an LP who is also the pool admin) captures this surplus as LP fee revenue.

### Likelihood Explanation
The pool admin is a semi-trusted role that any pool creator can assign to themselves. The call requires only `onlyPoolAdmin` — no timelock, no factory-owner approval. A pool admin who is also the primary LP has a direct financial incentive to set maximum bin additional fees to extract value from traders.

### Recommendation
Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. Introduce a `maxAdminBinFeeE6` parameter (settable by the factory owner, bounded by a hard constant) and enforce it:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminBinFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminBinFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

### Proof of Concept
1. Factory owner calls `setFeeCaps(..., newMaxAdminSpreadFeeE6 = 1000, ...)` to limit admin spread fees to 0.1 %.
2. Pool admin calls `setPoolAdminFees(pool, 1000, 0)` — accepted, at the cap.
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — **no revert**; bin 0 now carries 6.5535 % buy and sell additional fees.
4. A trader swaps through bin 0 and pays 6.5535 % + oracle spread in fees, far exceeding the factory owner's intended 0.1 % admin cap.
5. The excess fee accrues as LP revenue, benefiting the pool admin who is also the LP. [2](#0-1) [3](#0-2) [5](#0-4) [6](#0-5)

### Citations

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

**File:** metric-core/contracts/MetricOmmPool.sol (L996-1004)
```text
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
