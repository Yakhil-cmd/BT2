### Title
Bad-debt socialization uses hardcoded `liq-penalty-max` instead of the computed graduated `liq-penalty`, causing premature/incorrect socialization onto lenders - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
In `liquidate`, the logic that determines whether a borrower's remaining collateral can still cover their remaining debt (and therefore whether the position should be flagged as bad debt and socialized across all suppliers) uses the fixed group parameter `liq-penalty-max` in its conversion math, instead of the actual graduated `liq-penalty` computed for the specific liquidation event via `calc-liquidation-params`. This is the same bug class as the reported issue: a value that should be dynamically computed is instead hardcoded, and it drives a financial calculation that affects funds beyond the caller.

### Finding Description
`calc-liquidation-params` computes a graduated, LTV-dependent `liq-penalty` between `liq-penalty-min` and `liq-penalty-max` [1](#0-0) . This `liq-penalty` is correctly used for the primary debt/collateral conversion of the liquidated asset pair [2](#0-1) , [3](#0-2) .

However, two subsequent calculations that decide whether the position has "no collateral left" (and therefore whether bad debt gets socialized) instead hardcode `liq-penalty-max` as the divisor:

- `remaining-debt-to-repay`, used to decide whether the liquidator should take the borrower's *entire* remaining balance of the same collateral asset: [4](#0-3) 

- `other-debt-repayable`, used to estimate how much debt the borrower's *other* collateral assets could still cover: [5](#0-4) 

Both feed into `no-collateral-left`, which gates bad-debt socialization: [6](#0-5) 

Since `liq-penalty-max` is always ≥ the graduated `liq-penalty` actually applied to this liquidation (the penalty only reaches its max at full liquidation LTV), dividing the borrower's remaining collateral value by `(BPS + liq-penalty-max)` instead of `(BPS + liq-penalty)` systematically *understates* how much debt the borrower's remaining collateral can still cover. This makes `remaining-debt-to-repay` and `other-debt-repayable` resolve to zero more often than they should, which:
1. Causes the liquidator to be granted the borrower's *entire* remaining balance of a collateral asset instead of only the proportionate amount required — an over-seizure not properly bounded by the true, dynamically-computed penalty.
2. Causes `no-collateral-left` to evaluate `true` in situations where, under the correct (lower) `liq-penalty`, the borrower's other collateral would actually still be sufficient to back the remaining debt. This triggers `socialize-debt-asset` to spread the "bad debt" across all suppliers of the debt asset [7](#0-6)  even though the position was not truly insolvent.

The shared state harmed is the debt asset's supply-side accounting (interest/index shared by all lenders of that asset) — the `socialize-debt-asset` fold call directly mutates state consumed by every supplier of that market, not just the liquidator or the borrower being liquidated.

### Impact Explanation
This is a socialization charged to all suppliers of the debt asset: lenders who supplied capital into the affected vault absorb a loss (via bad-debt write-down of the shared borrow/supply index) that is not proportionate to the borrower's actual remaining collateral coverage, because the gating calculation used a hardcoded worst-case penalty (`liq-penalty-max`) rather than the graduated, dynamically-computed `liq-penalty` for that specific liquidation. This falls under temporary/permanent freezing or reduction of unclaimed yield for lenders in the affected vault, since the socialized loss reduces the effective yield/principal recoverable by suppliers who had no part in the transaction.

### Likelihood Explanation
This triggers on any liquidation where the graduated `liq-penalty` is meaningfully below `liq-penalty-max` (i.e., any liquidation that isn't at the fully-liquidatable LTV threshold, which is the majority of partial liquidations under the graduated curve design) and where the borrower holds collateral in an asset other than the one being liquidated, or a small remaining balance in the same asset. Because partial/graduated liquidations are the common case (that's the entire purpose of the curve), this is a routinely reachable path, not an edge case requiring privileged access.

### Recommendation
Replace `liq-penalty-max` with the already-computed `liq-penalty` (from `calc-liquidation-params`) in both the `remaining-debt-to-repay` calculation [8](#0-7)  and the `other-debt-repayable` calculation [9](#0-8) , so the "does the borrower have enough remaining collateral" check is consistent with the actual penalty rate applied to this liquidation, rather than a hardcoded worst-case constant.

### Proof of Concept
1. Borrower has two collateral assets, A (small balance, being liquidated) and B (large balance, not being liquidated), and one debt asset D.
2. Borrower's LTV is only slightly above `ltv-liq-partial`, so `calc-liquidation-params` returns a `liq-penalty` close to `liq-penalty-min` (e.g., 2%), far below `liq-penalty-max` (e.g., 15%).
3. Liquidator calls `liquidate` on collateral A. `coll-removed` for asset A becomes 0 (rounding/cap edge) — reachable because `debt-to-repay`/`coll-final` scaling can legitimately zero out for small remaining balances.
4. `other-coll-usd` (value of collateral B) is computed and divided by `(BPS + liq-penalty-max)` instead of `(BPS + liq-penalty)`, understating `other-debt-repayable`; if this understated value rounds to `u0` while the true value (using `liq-penalty`) would have been > 0, `no-collateral-left` incorrectly evaluates to `true`.
5. `socialize-debt-asset` is invoked, socializing the borrower's remaining debt in D across all suppliers of D's vault, even though collateral B's real market value (at the correct, lower penalty) was sufficient to cover it.
6. Result: lenders of asset D absorb an unwarranted loss caused solely by the hardcoded `liq-penalty-max` substitution.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L736-756)
```text
;; Graduated liquidation parameter calculation
;; Combines the 4-step liquidation factor calculation into a single helper
;; Returns: { liq-pct-scaled: uint, liq-penalty: uint, max-debt-usd: uint }
(define-private (calc-liquidation-params
  (current-ltv uint)
  (ltv-liq-partial uint)
  (ltv-liq-full uint)
  (liq-penalty-min uint)
  (liq-penalty-max uint)
  (curve-exponent uint)
  (total-debt-usd uint))
  
  (let ((liq-pct-linear (calc-liq-factor current-ltv ltv-liq-partial ltv-liq-full))
        (liq-pct-scaled (calc-liq-factor-exp liq-pct-linear curve-exponent))
        (liq-penalty (calc-liq-factor-bound liq-pct-scaled liq-penalty-min liq-penalty-max))
        (max-debt-usd (calc-liq-debt-repay total-debt-usd liq-pct-scaled)))
    {
      liq-pct-scaled: liq-pct-scaled,
      liq-penalty: liq-penalty,
      max-debt-usd: max-debt-usd
    }))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1437-1444)
```text
    ;; liquidation parameters (graduated liquidation calculation)
    (liq-params (calc-liquidation-params 
                  current-ltv ltv-liq-partial ltv-liq-full
                  liq-penalty-min liq-penalty-max 
                  curve-exponent total-debt-usd))
    (liq-pct-scaled (get liq-pct-scaled liq-params))
    (liq-penalty (get liq-penalty liq-params))
    (max-debt-usd (get max-debt-usd liq-params))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1462-1468)
```text
    ;; final liquidation amounts (with proportional adjustment if needed)
    (final-amounts (calc-final-liquidation-amounts
                     debt-actual-usd coll-actual coll-expected
                     coll-price coll-decimals
                     debt-price debt-decimals liq-penalty))
    (debt-final-usd (get debt-final-usd final-amounts))
    (debt-final (get debt-final final-amounts))
```

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1514-1525)
```text
          (target-coll-full-usd (normalize (* user-coll-balance coll-price) coll-decimals false))
          (other-coll-usd (if (> total-collateral-usd target-coll-full-usd)
                              (- total-collateral-usd target-coll-full-usd)
                              u0))
          (other-debt-repayable
            (if (> other-coll-usd u0)
              (let ((other-adj (div-bps-down other-coll-usd (+ BPS liq-penalty-max)))
                    (other-tokens (mul-div-down other-adj (pow u10 debt-decimals) debt-price))
                    (other-borrow-idx (get index (unwrap-panic (get-cached-indexes debt-aid))))
                    (other-scaled (mul-div-down other-tokens INDEX-PRECISION other-borrow-idx)))
                (mul-div-up other-scaled other-borrow-idx INDEX-PRECISION))
              u0))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1526-1560)
```text
          (no-collateral-left (and
                                (is-eq coll-removed u0)
                                (or
                                  (is-eq (len (get collateral pos-full)) u1)
                                  (and
                                    (is-eq (len (get collateral pos-full)) (len (get collateral position)))
                                    (is-eq other-debt-repayable u0))))))

      ;; Handle bad debt socialization if no collateral left
      (let ((bad-debt-socialized 
              (if no-collateral-left
                  (let ((stripped-debt-list (filter-out-debt-asset (get debt pos-full) debt-aid))
                        (fresh-debt-list (if (is-eq debt-updated u0)
                                             stripped-debt-list
                                             (unwrap-panic (as-max-len?
                                               (append stripped-debt-list
                                                       { aid: debt-aid, scaled: debt-updated })
                                               u64)))))
                    (if (> (len fresh-debt-list) u0) ;; if still has debt
                      (let ((socialization-result (fold socialize-debt-asset 
                                                        fresh-debt-list 
                                                        { borrower: borrower, success: true })))
                        (asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)
                        ;; emit bad-debt-socialized event
                        (print {
                          action: "bad-debt-socialized",
                          caller: contract-caller,
                          data: {
                            borrower: borrower,
                            debt-list: fresh-debt-list
                          }
                        })
                        true)
                      false))
                  false)))
```
