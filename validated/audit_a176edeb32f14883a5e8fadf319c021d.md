### Title
Incorrect graduated-liquidation curve exponent math causes excess collateral seizure from borrowers - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
### Finding Description
`calc-liq-factor-exp` is supposed to raise the linear liquidation factor to the configured `curve-exponent` power (`liq-factor = liq-factor^alpha`) to produce a graduated liquidation curve, analogous to the `unlockExponent` design described in the external report. [1](#0-0) 

However the implementation does not correctly generalize the exponent:
- When `exp` is strictly between `BPS` and `2*BPS` (i.e. any fractional alpha such as 1.01–1.99), `(/ exp BPS)` truncates to `1`, so `(pow factor 1) / (pow BPS 0)` simply returns `factor` unchanged — the configured super-linear curve silently collapses to linear for that whole range.
- When `exp < BPS` (any alpha < 1, e.g. 0.1, 0.2, 0.9), the code ignores the actual configured value entirely and always computes `(sqrti (* factor BPS))`, i.e. it hard-codes `alpha = 0.5` regardless of what `curve-exponent` was actually set to.

This exactly mirrors the reported bug class: the exponent-based scaling factor does not behave as intended for any exponent other than an exact multiple of `BPS`, producing a liquidation percentage/penalty that is systematically higher than the graduated curve intends for concave curves (any alpha < 0.5 gets inflated to the 0.5 curve, which ramps up liquidation percentage much faster near the partial-liquidation threshold).

`calc-liq-factor-exp`'s output (`liq-pct-scaled`) directly drives `calc-liq-factor-bound` (liquidation penalty) and `calc-liq-debt-repay` (max debt repayable, hence max collateral seized) in `calc-liquidation-params`. [2](#0-1) 

### Impact Explanation
Any permissionless liquidator (attacker) calling the liquidation entrypoint against a borrower (victim) whose position has just crossed the partial-liquidation LTV threshold will, for any egroup configured with a sub-linear curve exponent (`curve-exponent < BPS`), always be granted the `alpha = 0.5` liquidation percentage and penalty instead of the intended smaller value. This results in the liquidator seizing more of the borrower's collateral and being permitted to repay more debt than the graduated-liquidation design intends — a direct seizure exceeding its intended bound, at the borrower's expense, without the borrower's LTV or debt/collateral state changing. This is theft of the victim's collateral beyond what the configured curve authorizes, i.e. direct theft of user funds at rest.

### Likelihood Explanation
This triggers deterministically on every partial liquidation for any egroup whose `LIQ-CURVE-EXP` is not an exact multiple of `BPS` (the sub-linear branch is taken for the entire range `0 < exp < BPS`, and the super-linear branch collapses to linear for `BPS < exp < 2*BPS`). No special privileges are required — it fires on ordinary permissionless liquidation calls once a position becomes partially liquidatable.

### Recommendation
Fix `calc-liq-factor-exp` to correctly compute `factor^(exp/BPS)` for arbitrary fractional exponents (e.g. via a proper fixed-point power function, or by restricting `curve-exponent` to a small enumerated set of exactly-supported exponents such as 0.5, 1, 2, and validating/rejecting all other configured values), so that the liquidation percentage/penalty actually matches the documented graduated curve for the exponent that governance configured.

### Proof of Concept
1. Egroup is configured with `LIQ-CURVE-EXP = 2000` (intended alpha = 0.2, a gentle concave curve near the partial threshold).
2. Borrower's `current-ltv` rises just past `ltv-liq-partial`, producing a small linear `liq-pct-linear` (e.g. 500 bps out of 10000).
3. `calc-liq-factor-exp` takes the `exp < BPS` branch and computes `sqrti(500 * 10000) ≈ 2236` instead of the intended `500^0.2`-scaled value (which would be much smaller, close to `liq-pct-linear` since alpha=0.2 flattens the curve near 0).
4. This inflated `liq-pct-scaled` feeds into `calc-liq-factor-bound` (higher `liq-penalty`) and `calc-liq-debt-repay` (higher `max-debt-usd`), letting the liquidator (attacker) repay and seize roughly `2236/500 ≈ 4.5x` more of the victim's collateral value than the configured curve intended for that LTV, at no fault of the borrower. [3](#0-2)

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L706-756)
```text
;; Apply curve exponent for graduated liquidation
;; liq-factor = liq-factor^alpha
(define-private (calc-liq-factor-exp (factor uint) (exp uint))
  (if (is-eq exp BPS) 
    factor
    (if (> exp BPS) 
        (/ (pow factor (/ exp BPS)) (pow BPS (- (/ exp BPS) u1)))
        (sqrti (* factor BPS))))) ;; assume factor^0.5

;; Scale penalty between min and max using liquidation factor
;; liq-penalty = liq-penalty-min + (liq-factor * (liq-penalty-max - liq-penalty-min) / BPS)
;; Capped at bound-max to handle cases where liq-factor > BPS
(define-private (calc-liq-factor-bound (liq-factor uint) (bound-min uint) (bound-max uint))
  (min bound-max (+ bound-min (mul-bps-down liq-factor (- bound-max bound-min)))))

;; Calculate debt to repay based on liquidation factor
;; debt-repay = liq-factor * debt / BPS
(define-private (calc-liq-debt-repay (debt uint) (liq-factor uint)) 
  (mul-bps-down liq-factor debt))

;; Calculate collateral to seize (includes liquidator bonus)
;; collateral-repay = debt-repay * (BPS + liq-penalty) / BPS
(define-private (calc-liq-collateral-repay (debt-repay uint) (liq-penalty uint)) 
  (mul-bps-down debt-repay (+ BPS liq-penalty)))

;; Calculate actual debt repayment when collateral is capped
;; debt-repay-real = (collateral-amount-usd * BPS) / (BPS + liq-penalty)
(define-private (calc-liq-debt-repay-real (collateral-amount-usd uint) (liq-penalty uint)) 
  (div-bps-down collateral-amount-usd (+ BPS liq-penalty)))

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
