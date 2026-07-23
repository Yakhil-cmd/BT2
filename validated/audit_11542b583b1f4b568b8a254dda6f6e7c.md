### Title
Pool Admin Bypasses `maxAdminSpreadFeeE6` Cap via Uncapped `setPoolBinAdditionalFees` — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The factory enforces `maxAdminSpreadFeeE6` as a hard ceiling on pool-admin spread fees, but `setPoolBinAdditionalFees` passes per-bin additional fees directly to the pool with **no cap check**, allowing a pool admin to impose effective swap fees that exceed the factory owner's intended limit and extract excess value from traders.

---

### Finding Description

The factory owner controls `maxAdminSpreadFeeE6` and enforces it in `setPoolAdminFees`: [1](#0-0) 

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
```

However, the parallel pool-admin function `setPoolBinAdditionalFees` performs **no such cap check** before forwarding to the pool: [2](#0-1) 

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

The pool's `setBinAdditionalFees` also applies no cap — it only validates the bin index: [3](#0-2) 

```solidity
function setBinAdditionalFees(int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external onlyFactory nonReentrant(PoolActions.SET_BIN_ADDITIONAL_FEES)
{
    if (bin < LOWEST_BIN || bin > HIGHEST_BIN) revert InvalidBinIndex(bin);
    BinState storage s = _binStates[bin];
    s.addFeeBuyE6 = addFeeBuyE6;
    s.addFeeSellE6 = addFeeSellE6;
    emit BinAdditionalFeesUpdated(bin, addFeeBuyE6, addFeeSellE6);
}
```

In the swap path, the bin additional fee is **added** to the base spread fee: [4](#0-3) 

```solidity
(curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken0InBinSpecifiedOut(
    binState,
    curPosInBinCache,
    state,
    params.baseFeeX64 + Math.mulDiv(binState.addFeeBuyE6, ONE_X64, 1e6),
    ...
```

The effective fee a trader pays is `spreadFeeE6 + addFeeBuyE6`. Because `addFeeBuyE6` is `uint16` (max 65 535, i.e. 6.5535% in E6 units) and is never checked against `maxAdminSpreadFeeE6`, the pool admin can set it to `type(uint16).max` for every bin, bypassing whatever lower cap the factory owner configured.

---

### Impact Explanation

Traders swapping through any bin pay `spreadFeeE6 + addFeeBuyE6` as the effective fee. If the factory owner has set `maxAdminSpreadFeeE6 = 10 000` (1 %) to protect users, a malicious pool admin can still impose up to 6.5535 % additional fee per bin, making the real effective fee up to **7.5535 %** — 7.5× the intended cap. The excess fee accrues inside the pool's bin balances as LP profit, directly reducing the tokens traders receive. This is a direct loss of user principal on every swap.

---

### Likelihood Explanation

The pool admin is semi-trusted only within the caps and timelocks the factory owner sets. The bypass requires only a single `setPoolBinAdditionalFees` call per bin — no timelock, no co-signer, no special precondition. Any pool admin who turns adversarial (or whose key is compromised) can immediately exploit this against all future swappers in that pool.

---

### Recommendation

Add a cap check in `setPoolBinAdditionalFees` before forwarding to the pool:

```solidity
function setPoolBinAdditionalFees(address pool, int8 bin, uint16 addFeeBuyE6, uint16 addFeeSellE6)
    external override nonReentrant onlyPoolAdmin(pool)
{
    // Enforce the same admin spread-fee ceiling that setPoolAdminFees enforces
    if (uint256(addFeeBuyE6) + uint256(poolFeeConfig[pool].adminSpreadFeeE6) > maxAdminSpreadFeeE6)
        revert AdminFeeTooHigh();
    if (uint256(addFeeSellE6) + uint256(poolFeeConfig[pool].adminSpreadFeeE6) > maxAdminSpreadFeeE6)
        revert AdminFeeTooHigh();
    IMetricOmmPoolFactoryActions(pool).setBinAdditionalFees(bin, addFeeBuyE6, addFeeSellE6);
}
```

Alternatively, enforce the cap inside the pool's `setBinAdditionalFees` by reading the factory's `maxAdminSpreadFeeE6` at call time.

---

### Proof of Concept

1. Factory owner deploys factory and sets `maxAdminSpreadFeeE6 = 10_000` (1 %) via `setFeeCaps`.
2. A pool is created with `adminSpreadFeeE6 = 5_000` (0.5 %).
3. Pool admin calls `setPoolBinAdditionalFees(pool, 0, 65_535, 65_535)` for every bin — no revert occurs because there is no cap check.
4. A trader calls `swap(...)` through bin 0. The effective buy fee applied is `baseFeeX64 + mulDiv(65_535, ONE_X64, 1e6)` — approximately 6.5535 % additional on top of the spread fee, far exceeding the 1 % cap the factory owner intended.
5. The trader receives significantly fewer output tokens than the 1 %-capped fee would permit; the excess remains in the pool as LP profit, constituting a direct loss of user principal.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L906-915)
```text
          (curPosInBinCache, delta0Scaled, delta1Scaled, binLpFeeAmountScaled) = SwapMath.buyToken0InBinSpecifiedOut(
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
