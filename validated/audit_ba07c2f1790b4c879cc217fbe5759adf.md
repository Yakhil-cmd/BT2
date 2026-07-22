### Title
Pool Admin Can Sandwich Swappers via Uncapped `setPoolBinAdditionalFees` with No Timelock, Bypassing `maxAdminSpreadFeeE6` Cap — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolBinAdditionalFees` lets the pool admin set per-bin additional spread fees (`addFeeBuyE6`, `addFeeSellE6`) to any `uint16` value (up to 65 535 in E6 = 6.5535%) with **no cap check and no timelock**. This is structurally inconsistent with `setPoolAdminFees`, which is bounded by `maxAdminSpreadFeeE6`. A malicious-but-valid pool admin can front-run a pending swap, spike the active bin's additional fee to `uint16.max`, let the swap execute at the inflated rate, then restore the fee — extracting value from the swapper beyond what the protocol's fee-cap system is supposed to allow.

---

### Finding Description

`setPoolAdminFees` enforces hard caps:

```solidity
// MetricOmmPoolFactory.sol:408-435
function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    ...
}
``` [1](#0-0) 

`setPoolBinAdditionalFees` has **no such check**:

```solidity
// MetricOmmPoolFactory.sol:450-457
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool's `setBinAdditionalFees` also performs no cap validation: [3](#0-2) 

These per-bin fees are added directly on top of the oracle-derived base spread fee during every swap step:

```solidity
// MetricOmmPool.sol:540-541
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [4](#0-3) 

The resulting wider spread increases the pool's token surplus, which is then split between admin and protocol in `collectFees` proportionally to their stored fee components: [5](#0-4) 

So the admin **does** capture a share of the bin-additional-fee surplus, and can do so at any value up to `uint16.max` = 65 535 E6 = **6.5535%** per bin, per direction — with no timelock and no cap.

---

### Impact Explanation

A pool admin can execute the following sandwich:

1. Pool is operating with `addFeeBuyE6 = 0` on the active bin.
2. Swapper submits a swap transaction (e.g., via `MetricOmmSimpleRouter.exactInputSingle` with `amountOutMinimum = 0`, or directly to the pool).
3. Admin front-runs: calls `setPoolBinAdditionalFees(pool, curBinIdx, 65535, 0)` — sets buy-side additional fee to 6.5535%.
4. Swapper's swap executes: the effective buy fee is now `baseFeeX64 + 6.5535%`. The swapper receives ~6.5535% less output than the oracle price implied.
5. Admin back-runs: restores `addFeeBuyE6 = 0`.
6. Admin calls `collectPoolFees` to harvest the inflated surplus.

The corrupted value is the swapper's output token amount: they receive approximately `amountOut × (addFeeBuyE6 / 1e6)` fewer tokens than the oracle-fair price entitles them to. For a $1 M swap with `addFeeBuyE6 = 65535`, the swapper loses ~$65 535 in a single block.

This bypasses the `maxAdminSpreadFeeE6` cap (which is supposed to be the ceiling on admin fee extraction) because bin additional fees are a separate code path with no cap enforcement.

---

### Likelihood Explanation

- The pool admin is a **semi-trusted** role; the protocol's own documentation acknowledges they operate "only inside caps and timelocks."
- `setPoolBinAdditionalFees` requires only `onlyPoolAdmin` — no timelock, no multisig requirement, no delay.
- The attack is executable in two sequential transactions (front-run + back-run) or within a single block on chains with private mempools / flashbots.
- Users who call the pool directly (not through the router) have **zero** slippage protection. Router users are protected only if they set a non-zero `amountOutMinimum`.
- The bin additional fees are stored per-bin and are not reflected in the global `spreadFeeE6` view, so off-chain quote tools that read only `spreadFeeE6` will not warn the user.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` analogous to the one in `setPoolAdminFees`. The simplest fix is to bound the sum of base admin spread fee and bin additional fee against `maxAdminSpreadFeeE6`:

```solidity
function setPoolBinAdditionalFees(
    address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6
) external override nonReentrant onlyPoolAdmin(pool) {
    // Bin additional fees must not exceed the admin spread cap
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, consider adding a timelock to `setPoolBinAdditionalFees` consistent with the price-provider rotation timelock pattern already used in `proposePoolPriceProvider` / `executePoolPriceProviderUpdate`.

---

### Proof of Concept

```solidity
// Attacker = pool admin
// Setup: pool with curBinIdx = 0, addFeeBuyE6 = 0, reasonable spreadFeeE6

// Step 1: Victim submits swap tx (pending in mempool)
// pool.swap(recipient, false, 1_000_000e6, 0, "", "")

// Step 2: Admin front-runs (same block, higher gas)
factory.setPoolBinAdditionalFees(pool, 0, 65535, 0);
// addFeeBuyE6 on bin 0 is now 65535 (6.5535%)

// Step 3: Victim's swap executes
// buyFeeX64 = baseFeeX64 + 65535 * ONE_X64 / 1e6
// Victim receives ~6.5535% fewer tokens than oracle price implies

// Step 4: Admin back-runs
factory.setPoolBinAdditionalFees(pool, 0, 0, 0);

// Step 5: Admin collects inflated surplus
factory.collectPoolFees(pool);
// Admin receives their proportional share of the ~6.5535% extra spread
``` [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-395)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;

    unchecked {
      uint256 spreadFee0ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * adminSpreadFeeE6_) / spreadSumE6;

      uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * protocolSpreadFeeE6_) / spreadSumE6;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```
