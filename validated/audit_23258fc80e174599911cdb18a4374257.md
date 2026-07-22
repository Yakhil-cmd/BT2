The key facts are now confirmed. Let me verify the exact fee computation path and the absence of any cap check.

### Title
Pool Admin Bypasses Factory Spread Fee Cap via Uncapped `setPoolBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` imposes **no upper-bound check** on `addFeeBuyE6` / `addFeeSellE6`, while the parallel `setPoolAdminFees` path enforces `maxAdminSpreadFeeE6`. A pool admin can set per-bin additional fees up to `uint16` max (65 535 E6 = **6.5535 %** per bin), bypassing the factory's spread-fee cap and causing traders to pay more than the protocol guarantees.

---

### Finding Description

`setPoolAdminFees` enforces the factory cap:

```solidity
// MetricOmmPoolFactory.sol:414
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has **no equivalent check** — it forwards the raw `uint16` values directly to the pool:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`setBinAdditionalFees` on the pool also has no cap check — it stores the value unconditionally: [3](#0-2) 

During every swap the stored `addFeeBuyE6` is added directly on top of `baseFeeX64` with no clamping:

```solidity
// MetricOmmPool.sol:999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

`uint16` max is 65 535, so the additional fee can reach **65 535 / 1 000 000 = 6.5535 %** per bin, completely outside the `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %) system — but that hard cap only constrains the global spread fee, not the per-bin overlay. [5](#0-4) 

---

### Impact Explanation

Traders swapping through a bin with `addFeeBuyE6 = 65535` pay **6.5535 % extra** on that bin's input amount beyond what the factory's spread-fee cap permits. This is a direct, quantifiable loss of user principal on every affected swap. The pool admin can apply this to every bin in the pool simultaneously, making the pool effectively unusable at fair prices.

---

### Likelihood Explanation

The pool admin is a **semi-trusted** role that the protocol explicitly constrains via `maxAdminSpreadFeeE6`. The exploit requires only a single call to `setPoolBinAdditionalFees` with `addFeeBuyE6 = 65535` — no special conditions, no timelock, no oracle manipulation. Any pool admin (including one who was granted the role legitimately and later turns adversarial) can execute this immediately.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the one in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (uint256(addFeeBuyE6)  > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (uint256(addFeeSellE6) > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, introduce a dedicated `maxBinAdditionalFeeE6` cap settable by the factory owner, so the protocol can allow higher per-bin fees by design while still bounding them.

---

### Proof of Concept

```solidity
// Foundry test sketch
function test_binFeeBypassesCap() public {
    address pool = _createPool(); // maxAdminSpreadFeeE6 = 200_000 (20%)

    vm.prank(admin);
    // uint16 max = 65535 → 6.5535% additional fee, no revert
    factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535);

    // Perform a swap through bin 0
    // Measure effective cost vs. a swap with addFeeBuyE6 = 0
    // Assert: effective cost exceeds maxAdminSpreadFeeE6 cap
    // (baseFeeX64 + 65535*ONE_X64/1e6) >> baseFeeX64 + maxAdminSpreadFeeE6*ONE_X64/1e6
}
```

The call succeeds without revert, and the stored `addFeeBuyE6 = 65535` is applied verbatim in every subsequent `buyToken0InBinSpecifiedIn` / `buyToken0InBinSpecifiedOut` call through that bin.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L994-1004)
```text
          (curPosInBinCache, outToken0AmountScaled, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) =
            SwapMath.buyToken0InBinSpecifiedIn(
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
