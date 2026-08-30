Based on my analysis, I found a valid analog in the liquidation dust-handling logic of `market.clar` / `v0-4-market.clar`, where a wrong-quantity comparison (checking a rounded debt-equivalent value against zero) is used to decide whether to seize a borrower's entire collateral balance rather than the computed partial amount — an over-seizure not compensated by additional debt repayment.

### Title
Dust-triggered full-collateral seizure lets a liquidator take more collateral than the debt repaid justifies - (File: `mainnet/contracts/market/v0-4-market.clar`, function `liquidate`)

### Summary
In `liquidate`, the amount of a specific collateral asset actually taken from the borrower is decided by comparing a derived, rounded quantity (`remaining-debt-to-repay`, the USD-value-turned-scaled-debt equivalent of the leftover "dust" collateral) against zero, instead of comparing the dust collateral amount itself against a meaningful minimum. When this rounded value rounds down to zero, the code silently switches from taking the computed partial `coll-final-raw` amount to taking the borrower's *entire* balance of that asset (`user-coll-balance`), while `debt-to-repay` (computed earlier from `debt-final`) is never increased to compensate. This mirrors the `ManagedIndexReweightingLogic.reweight` bug class: a `requirement`/branch condition compares the wrong derived quantity, causing an outcome that doesn't match the actual invariant it's meant to enforce.

### Finding Description
Relevant code: [1](#0-0) 

```
(coll-remaining (- user-coll-balance coll-final-raw))
(remaining-debt-to-repay
  (if (> coll-remaining u0)
    (let ((rem-coll-usd (normalize (* coll-remaining coll-price) coll-decimals false))
          (rem-debt-usd (div-bps-down rem-coll-usd (+ BPS liq-penalty-max)))
          (rem-debt-tokens (mul-div-down rem-debt-usd (pow u10 debt-decimals) debt-price))
          (rem-borrow-index (get index (unwrap-panic (get-cached-indexes debt-aid))))
          (rem-scaled (mul-div-down rem-debt-tokens INDEX-PRECISION rem-borrow-index)))
      (mul-div-up rem-scaled rem-borrow-index INDEX-PRECISION))
    u1))
(coll-final (if (is-eq remaining-debt-to-repay u0) user-coll-balance coll-final-raw)))
```

`coll-final-raw` is the collateral amount computed by `scale-debt-for-liquidation` to correspond precisely to `debt-to-repay` (the scaled debt actually being removed from the borrower's position). `coll-remaining` is the leftover collateral of this asset after that partial seizure. The code's intent is presumably to avoid leaving unliquidatable "dust" collateral stuck on a position with no debt left to justify liquidating it further. But the check `(is-eq remaining-debt-to-repay u0)` — computed by converting dust collateral value → USD → debt tokens → scaled debt, with two down-roundings and one up-rounding — evaluates to zero whenever the dust amount is small enough relative to `debt-decimals`/`debt-price`/`rem-borrow-index` scaling, which can occur even when the raw `coll-remaining` (in the collateral asset's native units) is non-trivial for low-decimal or high-value assets (e.g. sBTC with 8 decimals).

When this triggers, `coll-final` jumps from `coll-final-raw` to `user-coll-balance` — i.e., the *entire* remaining balance of that collateral asset — but `debt-to-repay` (used in `vault-system-repay` at line 1496) and the scaled debt removed (`scaled-to-remove`, used in `debt-remove-scaled` at line 1499-1503) were already fixed earlier from `debt-final`/`scale-debt-for-liquidation`, based on the smaller `coll-final-raw`. Only `min-collateral-expected` (a liquidator-supplied slippage floor, line 1493) gates the final `coll-final`, which only protects the liquidator from getting *too little*, not the borrower from losing *too much*. [2](#0-1) 

### Impact Explanation
The borrower (victim) has more of a specific collateral asset seized by the liquidator (attacker/beneficiary) than the debt actually repaid justifies under the protocol's own liquidation-factor/penalty math — the "extra" dust portion is transferred for free, with no offsetting debt reduction beyond what was already computed for the smaller `coll-final-raw` amount. This is a direct seizure exceeding its bound: theft of borrower funds at rest, which falls under the Critical impact class (direct theft of user funds).

### Likelihood Explanation
The liquidator fully controls `debt-amount` and can compute (via `get-cached-indexes`, `get-egroup`, and public asset/price data) the exact partial-liquidation math off-chain, then choose a `debt-amount` such that the leftover `coll-remaining` for the targeted collateral asset lands in the "dust" zone that rounds `remaining-debt-to-repay` to zero, while still keeping `coll-final-raw` (and thus `coll-final` post-trigger) comfortably above their own `min-collateral-expected`. Any position with a partial-liquidation state (LTV between `ltv-liq-partial` and `ltv-liq-full`) is exploitable this way, and liquidation is a normal, frequently-triggered, unprivileged action.

### Recommendation
Do not decide "take all remaining collateral" based on a rounded/derived debt-equivalent value. Instead:
- Compare the raw `coll-remaining` collateral amount (or its USD value) directly against an explicit dust threshold expressed in the same units, independent of debt-token rounding, or
- If leftover collateral is swept as dust, correspondingly increase `debt-to-repay`/`scaled-to-remove` by the equivalent amount so the borrower's debt reduction matches the extra collateral taken, preserving the liquidation-factor invariant.

### Proof of Concept
1. Borrower has a partial-liquidation-eligible position with collateral asset `coll-aid` (e.g., sBTC, 8 decimals) and debt asset `debt-aid`.
2. Liquidator computes the exact `debt-amount` at which `scale-debt-for-liquidation` yields a `coll-final-raw` that leaves `coll-remaining > 0` but small enough that, after `normalize`/`div-bps-down`/`mul-div-down`/`mul-div-up` through USD and scaled-debt conversions (lines 1479-1485), `remaining-debt-to-repay` rounds to `u0`.
3. Liquidator calls `liquidate` with that `debt-amount` and a `min-collateral-expected` set to (or below) `coll-final-raw`.
4. `coll-final` is set to `user-coll-balance` (line 1486) instead of `coll-final-raw`, but `debt-to-repay`/`scaled-to-remove` remain based on the smaller `debt-final`.
5. `collateral-remove` (line 1506-1512) transfers the borrower's *entire* balance of that collateral asset to the liquidator, while the borrower's debt is only reduced by the originally-computed partial amount — the borrower loses the dust remainder for free.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1476-1486)
```text
    (coll-remaining (- user-coll-balance coll-final-raw))
    (remaining-debt-to-repay
      (if (> coll-remaining u0)
        (let ((rem-coll-usd (normalize (* coll-remaining coll-price) coll-decimals false))
              (rem-debt-usd (div-bps-down rem-coll-usd (+ BPS liq-penalty-max)))
              (rem-debt-tokens (mul-div-down rem-debt-usd (pow u10 debt-decimals) debt-price))
              (rem-borrow-index (get index (unwrap-panic (get-cached-indexes debt-aid))))
              (rem-scaled (mul-div-down rem-debt-tokens INDEX-PRECISION rem-borrow-index)))
          (mul-div-up rem-scaled rem-borrow-index INDEX-PRECISION))
        u1))
    (coll-final (if (is-eq remaining-debt-to-repay u0) user-coll-balance coll-final-raw)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1490-1496)
```text
    (asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)

    ;; execute liquidation
    (try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))
```
