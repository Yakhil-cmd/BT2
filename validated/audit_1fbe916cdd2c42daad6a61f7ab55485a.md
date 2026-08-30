### Title
Bad-debt socialization decision computed with the fixed `LIQ-PENALTY-MAX` instead of the position's actual (current) liquidation penalty - (File: `mainnet/contracts/market/v0-4-market.clar`, `liquidate`)

### Summary
`liquidate` decides whether to write off ("socialize") a borrower's remaining debt to all vault suppliers by valuing the borrower's *other* (non-liquidated) collateral using the egroup's static `LIQ-PENALTY-MAX` bound rather than the `liq-penalty` actually computed for the current graduated liquidation (`current-ltv`). This is the same bug class as the Olympus finding: a boundary/"wall" value is substituted for the dynamically computed "current" value, producing an economically wrong result that is charged to third parties instead of the caller.

### Finding Description
In `calc-liquidation-params`, the protocol computes a graduated, LTV-dependent `liq-penalty` for the position being liquidated: [1](#0-0) 

This `liq-penalty` (the "current" value, analogous to Operator.sol's current market price) is correctly used to size the collateral actually seized in this call, via `process-collateral-asset`: [2](#0-1) 

However, when the function subsequently evaluates the borrower's *other* collateral assets (assets not chosen by the liquidator in this call) to decide whether the position has effectively "no collateral left" and thus its remaining debt should be socialized onto all suppliers of the debt vault, it discards `liq-penalty` and instead uses the egroup's static ceiling `LIQ-PENALTY-MAX` (the "wall"): [3](#0-2) 

The same substitution is made for `remaining-debt-to-repay`, which determines whether dust collateral gets swept in full: [4](#0-3) 

`LIQ-PENALTY-MAX` is, by construction of `calc-liq-factor-bound`, greater than or equal to the actual `liq-penalty` for any position that is not already at full liquidation: [5](#0-4) 

Dividing `other-coll-usd` by `(BPS + liq-penalty-max)` instead of `(BPS + liq-penalty)` produces a smaller `other-debt-repayable` than the position's actual current liquidation economics justify. When `other-debt-repayable` rounds to zero (e.g., for small residual collateral balances in other assets), `no-collateral-left` becomes `true` even though, at the position's actual current penalty rate, that collateral would still have covered some/all of the remaining debt. The result: `bad-debt-socialized` fires and marks a debt tranche as bad debt to be spread across vault depositors: [6](#0-5) 

### Impact Explanation
The victims are the depositors/suppliers of the debt vault (`.v0-vault-*`), an unprivileged and unrelated party to the liquidator and borrower. The liquidator (attacker or any caller, since `liquidate` is permissionless) can trigger a liquidation call in which this mispriced check causes debt to be prematurely and unnecessarily classified as unrecoverable and socialized, when the borrower's remaining collateral (valued at the position's real, lower `liq-penalty`) would have covered it. This directly diminishes the value backing all outstanding vault shares (`z*` tokens) held by other depositors — a socialization charged to all suppliers rather than an economically justified write-off. This falls under "temporary/permanent freezing of funds"/loss of yield for the vault's LPs (their claim on the pool decreases when bad debt is socialized without cause), an in-scope High/Critical-adjacent impact class.

### Likelihood Explanation
`liquidate` is callable by any address against any liquidatable position and passes borrower-selected `debt-amount`/collateral asset choices; the residual/"other" collateral valuation path is exercised on every liquidation where the borrower holds more than one collateral asset, which is a routine multi-collateral scenario. No privileged role or DAO action is required — an ordinary liquidator triggers the miscomputation as a side effect of a normal liquidation, so likelihood is high whenever borrowers use multiple collateral types and their position isn't already at the `LTV-LIQ-FULL` boundary (where `liq-penalty == liq-penalty-max` and the bug has no effect).

### Recommendation
Use the position's actual computed `liq-penalty` (not the static `LIQ-PENALTY-MAX` egroup bound) consistently everywhere collateral-vs-debt coverage is evaluated for the socialization decision — specifically in the `rem-debt-usd` calculation (line ~1480) and the `other-debt-repayable`/`other-adj` calculation (line ~1520). This aligns the "is there enough collateral left" check with the same penalty rate actually applied to the liquidation, preventing debt from being marked as bad/socialized based on an artificially pessimistic (max-penalty) valuation of the borrower's remaining collateral.

### Proof of Concept
1. Borrower opens a position with two collateral assets, A and B, and one debt asset D, such that `current-ltv` places the position in a partial (graduated) liquidation band, i.e., `ltv-liq-partial <= current-ltv < ltv-liq-full`, so the computed `liq-penalty < liq-penalty-max`.
2. A liquidator calls `liquidate(borrower, collateral-ft=A, debt-ft=D, debt-amount, ...)`, fully consuming collateral A for the debt portion allotted to it.
3. Borrower's remaining collateral B has a small USD value such that: `other-coll-usd / (BPS + liq-penalty) > 0` after conversion to debt tokens (i.e., would be nonzero and could still repay some debt at the real penalty), but `other-coll-usd / (BPS + liq-penalty-max)` rounds down to `0` in `other-tokens`/`other-scaled` due to the inflated divisor.
4. `other-debt-repayable` computes to `0`, `no-collateral-left` evaluates `true`, and the fold over `socialize-debt-asset` marks the borrower's remaining debt as bad debt, socializing it onto all suppliers of the debt vault D — even though collateral B, valued correctly, still had recoverable value.
5. Because this depends only on calling `liquidate` with ordinary parameters (no governance or oracle manipulation needed), the deviation is triggered by any unprivileged liquidator interacting with a normal multi-collateral position.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1453-1460)
```text
    ;; collateral processing
    (user-coll-balance (find-collateral-amount (get collateral pos-full) coll-aid))
    (coll-info (process-collateral-asset coll-aid debt-actual-usd liq-penalty 
                                         user-coll-balance assets coll-asset))
    (coll-actual (get coll-actual coll-info))
    (coll-expected (get coll-expected coll-info))
    (coll-price (get coll-price coll-info))
    (coll-decimals (get coll-decimals coll-info))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1514-1532)
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
          (no-collateral-left (and
                                (is-eq coll-removed u0)
                                (or
                                  (is-eq (len (get collateral pos-full)) u1)
                                  (and
                                    (is-eq (len (get collateral pos-full)) (len (get collateral position)))
                                    (is-eq other-debt-repayable u0))))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1534-1560)
```text
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
