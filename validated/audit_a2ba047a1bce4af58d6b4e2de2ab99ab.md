The code path is fully traceable. Here is the analysis:

**Step 1 — Factory entrypoint for pool admin:**

`MetricOmmPoolFactory.setPoolBinAdditionalFees` (lines 450–457) accepts `uint16 addFeeBuyE6` and `uint16 addFeeSellE6` from the pool admin and forwards them directly to the pool with **zero cap validation**:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [1](#0-0) 

**Step 2 — Contrast with the capped path:**

`setPoolAdminFees` (lines 414–415) explicitly enforces the cap:
```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [2](#0-1) 

No equivalent guard exists in `setPoolBinAdditionalFees`.

**Step 3 — Pool-level: also no cap:**

`MetricOmmPool.setBinAdditionalFees` (lines 464–474) only checks the bin index range, then writes the values directly:
```solidity
s.addFeeBuyE6 = addFeeBuyE6;
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

**Step 4 — Swap-time effect:**

The per-bin fee is added on top of `baseFeeX64` (derived from the oracle bid/ask spread) in every swap calculation:
```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

And in the full swap loop:
```solidity
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
``` [5](#0-4) 

**Step 5 — Quantifying the bypass:**

- `uint16.max = 65535` in E6 units = **6.5535%** additional fee per bin.
- `maxAdminSpreadFeeE6` defaults to `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%) but the factory owner can lower it (e.g., to 1% = 10,000).
- If `maxAdminSpreadFeeE6` is set to 10,000 (1%), the pool admin is blocked from setting the global admin spread fee above 1% via `setPoolAdminFees`, but can freely set per-bin fees to 65,535 (6.5535%) — **6.5× the intended cap** — with no revert. [6](#0-5) 

**Step 6 — Role boundary assessment:**

The contest scope explicitly states: *"pool admin is semi-trusted only inside caps and timelocks; look for bypasses in `setPoolFees`, `setBinAdditionalFees`, pause transitions..."* — `setBinAdditionalFees` is named as a bypass surface. The pool admin is not a trusted factory owner; they are constrained by `maxAdminSpreadFeeE6`. The per-bin path circumvents that constraint entirely.

---

### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped Per-Bin Additional Fees — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `uint16 addFeeBuyE6` / `addFeeSellE6` to the pool with no validation against `maxAdminSpreadFeeE6`, allowing the pool admin to impose per-bin spread fees up to `uint16.max` (6.5535% in E6) regardless of the factory-enforced admin fee cap.

### Finding Description
`setPoolAdminFees` enforces `if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh()` before updating the global admin spread component. `setPoolBinAdditionalFees` has no analogous check — it calls `pool.setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6)` directly. The pool's `setBinAdditionalFees` only validates the bin index range. At swap time, `addFeeBuyE6` and `addFeeSellE6` are added on top of `baseFeeX64` (the oracle-derived mid-spread) for every swap touching that bin, making the effective per-bin fee `globalSpreadFee + addFeeE6`. A pool admin can set `addFeeBuyE6 = addFeeSellE6 = 65535` (6.5535%) on every bin, bypassing whatever `maxAdminSpreadFeeE6` the factory owner has configured.

### Impact Explanation
Traders executing swaps in affected bins pay a higher effective spread than the `maxAdminSpreadFeeE6` boundary permits. The excess fee is extracted from the trader's swap output (bad-price execution). If the factory owner has tightened `maxAdminSpreadFeeE6` to, say, 1%, the pool admin can still impose 6.5535% per-bin — a 6.5× overcharge — on every swap in every bin. This is a direct, quantifiable loss to traders and constitutes an admin-boundary break under the contest's allowed impact gate.

### Likelihood Explanation
Any pool admin (a semi-trusted role, not a trusted factory owner) can call `setPoolBinAdditionalFees` at any time with no preconditions beyond holding the `poolAdmin[pool]` role. No timelock, no cap, no revert path exists. Likelihood is medium — it requires a malicious or compromised pool admin, but the path is a single permissioned call with no friction.

### Recommendation
Add a cap check in `MetricOmmPoolFactory.setPoolBinAdditionalFees` before forwarding to the pool:
```solidity
if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```
Alternatively, define a dedicated `maxAdminBinFeeE6` cap (since per-bin fees are `uint16` and the global cap is `uint24`) and enforce it here.

### Proof of Concept
```solidity
// Foundry test sketch
function test_binFeeBypassesAdminCap() public {
    // Factory owner tightens admin spread cap to 1%
    factory.setFeeCaps(200_000, 10_000, 1_000_000, 1_000_000);

    address pool = _createPool(); // adminSpreadFeeE6 = 0 at creation

    // Pool admin cannot set global admin fee above 1%
    vm.prank(admin);
    vm.expectRevert(IMetricOmmPoolFactory.AdminFeeTooHigh.selector);
    factory.setPoolAdminFees(pool, 10_001, 0);

    // But pool admin CAN set per-bin fee to uint16.max (6.5535%) — no revert
    vm.prank(admin);
    factory.setPoolBinAdditionalFees(pool, 0, type(uint16).max, type(uint16).max);

    // Verify stored value exceeds maxAdminSpreadFeeE6
    (,,, uint16 buyFee, uint16 sellFee) = PoolStateLibrary._binState(pool, 0);
    assertEq(buyFee, type(uint16).max);          // 65535 > 10000 (maxAdminSpreadFeeE6)
    assertGt(uint256(buyFee), factory.maxAdminSpreadFeeE6()); // invariant violated
}
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L469-473)
```text
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L910-910)
```text
            params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
```
