The code trace is complete. Here is the determination:

---

### Title
Pool Admin Bypasses Factory Fee Cap via Uncapped `setBinAdditionalFees` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`MetricOmmPoolFactory.setPoolBinAdditionalFees` passes `addFeeBuyE6` / `addFeeSellE6` directly to the pool with no cap check, while the parallel admin-fee setter `setPoolAdminFees` enforces `maxAdminSpreadFeeE6`. A pool admin can set `addFeeBuyE6 = 65535` (the `uint16` maximum, equal to 6.5535% in E6 units) on any bin, causing every swap through that bin to pay a fee above the factory-enforced ceiling, extracting excess token1 from traders.

### Finding Description

`setPoolAdminFees` enforces the factory cap:

```solidity
// MetricOmmPoolFactory.sol:414
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` has **no equivalent check**:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
  external override nonReentrant onlyPoolAdmin(pool)
{
  IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

`MetricOmmPool.setBinAdditionalFees` also performs no cap validation — it only checks the bin index range:

```solidity
// MetricOmmPool.sol:464-474
s.addFeeBuyE6 = addFeeBuyE6;   // stored unchecked
s.addFeeSellE6 = addFeeSellE6;
``` [3](#0-2) 

During every swap through that bin, the uncapped value is added directly to the base fee:

```solidity
// MetricOmmPool.sol:999
params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6)
``` [4](#0-3) 

The hard cap for all spread fees is `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20%): [5](#0-4) 

The bin additional fee is a `uint16`, so its maximum is 65535 / 1e6 = **6.5535%**, which is additive on top of the already-capped base spread fee. There is no factory-level ceiling that accounts for this additive component.

### Impact Explanation
Traders swapping in the affected bin pay up to 6.5535% more than the factory-enforced ceiling allows. The excess fee is taken from the trader's token1 input and credited to the pool (LP fee portion) or protocol (protocol fee portion), constituting direct loss of user principal above the factory-guaranteed maximum. This is an admin-boundary break: the pool admin exceeds the caps the factory is designed to enforce.

### Likelihood Explanation
The pool admin is a semi-trusted role. Any pool admin — including one that is malicious, compromised, or acting in self-interest — can call `setPoolBinAdditionalFees` at any time with no timelock, no cap, and no prior collection step. The call is a single transaction with immediate effect on all subsequent swaps in that bin.

### Recommendation
Add a cap check in `MetricOmmPoolFactory.setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`:

```solidity
if (uint256(addFeeBuyE6) + uint256(addFeeSellE6) > maxAdminSpreadFeeE6)
    revert AdminFeeTooHigh();
```

Or introduce a dedicated `maxBinAdditionalFeeE6` cap and enforce it there. The pool-level `setBinAdditionalFees` should also validate against a cap passed from the factory, or the factory should be the sole enforcement point.

### Proof of Concept

1. Deploy a pool with `spreadFeeE6 = S` (any value within caps).
2. Pool admin calls `factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)` — succeeds with no revert.
3. Trader calls swap routing through bin 0.
4. `SwapMath.buyToken0InBinSpecifiedIn` is called with `currBinBuyFeeX64 = baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)`.
5. The effective fee rate is `S/1e6 + 65535/1e6 = (S + 65535)/1e6`, which exceeds `maxAdminSpreadFeeE6/1e6` by 65535/1e6 = 6.5535% when `S` is already at the admin cap.
6. Assert `effectiveFeeE6 > maxAdminSpreadFeeE6` — assertion passes, confirming the bypass.

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
