### Title
Pool Admin Can Instantly Raise Per-Bin Fees to Uncapped `uint16.max` to Sandwich Trader Swaps — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolBinAdditionalFees` enforces **no cap** on `addFeeBuyE6`/`addFeeSellE6` and has **no timelock**, while the parallel global-fee setter `setPoolAdminFees` is strictly capped. A pool admin can front-run a pending swap by raising per-bin fees to `uint16.max` (65 535 E6 ≈ 6.55 %), causing the trader to pay materially more than the fee-cap system permits, then restore fees in the same block.

---

### Finding Description

`setPoolAdminFees` enforces explicit caps before writing to the pool:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
``` [1](#0-0) 

`setPoolBinAdditionalFees` performs **no such check** — it passes the caller-supplied values straight through to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
``` [2](#0-1) 

The pool stores these values in `BinState.addFeeBuyE6` / `addFeeSellE6` (both `uint16`, max 65 535) and applies them additively on top of the oracle-derived base spread fee during every swap in that bin:

```solidity
uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
``` [3](#0-2) 

The same additive path is used inside `_executeSwap` for every bin traversed: [4](#0-3) 

The `BinState` struct confirms the uncapped `uint16` fields: [5](#0-4) 

The hard caps for the global spread fee are `HARD_MAX_SPREAD_FEE_E6 = 200_000` (20 %) and `HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000` (1 %): [6](#0-5) 

Per-bin fees have **no analogous hard cap**. `uint16.max` = 65 535 E6 ≈ **6.55 %** additional fee per bin, on top of whatever global spread is already active. There is also no timelock on `setPoolBinAdditionalFees`, unlike the price-provider rotation path which enforces `priceProviderTimelock`. [7](#0-6) 

The swap's `priceLimitX64` parameter is checked against the **marginal price** (before fees), so it does not protect the trader against a fee increase applied in the same block.

---

### Impact Explanation

A trader who observes `addFeeBuyE6 = 0` on the active bin and submits a swap is exposed to the following sandwich:

1. Admin front-runs: `factory.setPoolBinAdditionalFees(pool, curBin, 65535, 65535)` — instant, no timelock.
2. Trader's `swap` executes; the bin walk applies `buyFeeX64 = baseFeeX64 + 65535/1e6 * ONE_X64`, charging ≈ 6.55 % extra on the input amount.
3. Admin back-runs: `factory.setPoolBinAdditionalFees(pool, curBin, 0, 0)` — restores state.

The excess fee accrues to LPs in the bin's token balance. If the admin is also an LP (or controls the LP position), they directly pocket the difference. Even without LP ownership, the admin extracts value from the trader by degrading execution quality beyond what the fee-cap system is supposed to permit. This is a **direct loss of user principal** and an **admin-boundary break**: the pool admin exceeds the effective fee cap by using the uncapped per-bin path.

---

### Likelihood Explanation

- The pool admin is semi-trusted and controls a single EOA or multisig; no additional privilege escalation is required.
- The attack requires only mempool visibility (standard on most EVM chains) and two factory calls bookending the victim's swap.
- No timelock, no proposal step, no co-signer — the entire sandwich fits in one block.
- The attack is repeatable on every swap in the targeted bin.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` mirroring the check in `setPoolAdminFees`:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (addFeeBuyE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (addFeeSellE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Optionally introduce a dedicated `maxAdminBinAdditionalFeeE6` cap and/or a short timelock (e.g., one block) on per-bin fee changes to prevent same-block sandwiching.

---

### Proof of Concept

```
State before:
  pool active bin = 0, addFeeBuyE6 = 0, spreadFeeE6 = 10_000 (1%)

Block N:
  Tx 1 (admin, higher gas): factory.setPoolBinAdditionalFees(pool, 0, 65535, 65535)
    → BinState[0].addFeeBuyE6 = 65535  (6.5535% additional)

  Tx 2 (trader): pool.swap(zeroForOne=true, amountSpecified=1000e18, priceLimitX64=...)
    → buyFeeX64 = baseFeeX64 + mulDiv(65535, ONE_X64, 1e6)
    → trader pays ≈ 7.55% total fee instead of expected 1%
    → excess ≈ 6.55% of 1000e18 = 65.5 tokens lost by trader

  Tx 3 (admin): factory.setPoolBinAdditionalFees(pool, 0, 0, 0)
    → BinState[0].addFeeBuyE6 = 0  (restored)

Net: trader lost ~65.5 tokens; LP balance in bin increased by that amount.
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L487-490)
```text
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L540-541)
```text
    uint256 buyFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6);
    uint256 sellFeeX64 = baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L1177-1178)
```text
              params.baseFeeX64 + Math.mulDiv(binState.addFeeSellE6, ONE_X64, 1e6),
              lowerPriceX64,
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
