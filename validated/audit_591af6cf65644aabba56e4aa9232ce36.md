Based on my code review, this is a **valid vulnerability**. Here is the full finding:

---

### Title
Pool Admin Bypasses Factory Fee Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` forwards `addFeeBuyE6` / `addFeeSellE6` directly to the pool with **no cap check**, while the analogous `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees to `type(uint16).max` (65535, ≈6.55% in E6 units) on any bin, bypassing the factory's intended fee ceiling and causing direct loss of trader input tokens.

---

### Finding Description

`setPoolAdminFees` enforces the factory cap:

```solidity
// MetricOmmPoolFactory.sol:414-415
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

But `setPoolBinAdditionalFees` has **no equivalent guard**:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool-side `setBinAdditionalFees` also performs no cap check — it only validates the bin index:

```solidity
// MetricOmmPool.sol:464-474
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
  if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
  BinState storage s = _binStates[bin];
  s.addFeeBuyE6 = addFeeBuyE6;
  s.addFeeSellE6 = addFeeSellE6;
  emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
``` [3](#0-2) 

`BinState.addFeeBuyE6` is a `uint16`, so the unchecked maximum is 65535 (≈6.55% in E6 units): [4](#0-3) 

The factory's `maxAdminSpreadFeeE6` (hard-capped at 20% by `HARD_MAX_SPREAD_FEE_E6 = 200_000`) is the intended ceiling for all pool-admin-controlled fees: [5](#0-4) 

The bin additional fee path is a separate, uncapped channel that lets the pool admin exceed this ceiling.

---

### Impact Explanation

- A pool admin sets `addFeeBuyE6 = 65535` on one or more bins.
- Every swap that routes through those bins pays an extra ≈6.55% on top of the spread fee, with no factory-enforced ceiling.
- If `maxAdminSpreadFeeE6` is, say, 1% (10000 E6), the pool admin can still extract 7.55% total from traders on those bins — a 6.55% excess beyond the disclosed cap.
- The excess fee is taken from trader input tokens, constituting direct loss of user principal above any Sherlock threshold.

---

### Likelihood Explanation

The pool admin is explicitly semi-trusted and is expected to operate within factory-enforced caps. The cap exists for spread fees (`setPoolAdminFees`) but is absent for bin additional fees (`setPoolBinAdditionalFees`). Any pool admin — including one who turns adversarial after deployment — can exploit this immediately with a single transaction, with no timelock or other delay.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool, analogous to the check in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxAdminBinAdditionalFeeE6` cap configurable by the factory owner, so the ceiling for per-bin fees can be set independently of the global spread fee cap.

---

### Proof of Concept

```solidity
// Foundry test sketch
function test_binFeeBypassesCap() public {
    address pool = factory.createPool(...); // maxAdminSpreadFeeE6 = 10_000 (1%)

    vm.prank(admin);
    // No revert — no cap check exists
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Trader swaps through bin 0
    uint256 traderInputBefore = token0.balanceOf(trader);
    vm.prank(trader);
    pool.swap(...);
    uint256 traderInputAfter = token0.balanceOf(trader);

    // Assert trader paid ~6.55% additional fee beyond the 1% cap
    uint256 extraFee = traderInputBefore - traderInputAfter - expectedAmountWithCap;
    assertGt(extraFee, 0); // direct loss
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

**File:** metric-core/contracts/types/PoolStorage.sol (L19-25)
```text
struct BinState {
  uint104 token0BalanceScaled;
  uint104 token1BalanceScaled;
  uint16 lengthE6;
  uint16 addFeeBuyE6;
  uint16 addFeeSellE6;
}
```
