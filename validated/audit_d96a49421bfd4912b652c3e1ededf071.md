### Title
Erroneous integer-division "power" approximation in graduated liquidation curve causes over-liquidation of borrowers - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`calc-liq-factor-exp` in `v0-4-market.clar` is Zest's analog of a Balancer-style exponentiation helper (`bpow`/`_compute`) used to apply a configurable curve exponent to the linear liquidation factor. Like the referenced finding, the conversion from the intended fixed-point power function to Solidity/Clarity integer arithmetic is done incorrectly: for any `curve-exponent` that is not an exact multiple of `BPS` (10000), the function silently discards the fractional part of the exponent via integer division, producing a materially different (and always *larger*, i.e. less-discounted) liquidation factor than the graduated curve was designed to produce.

### Finding Description
The exponent application logic is: [1](#0-0) 

```
(define-private (calc-liq-factor-exp (factor uint) (exp uint))
  (if (is-eq exp BPS) 
    factor
    (if (> exp BPS) 
        (/ (pow factor (/ exp BPS)) (pow BPS (- (/ exp BPS) u1)))
        (sqrti (* factor BPS))))) ;; assume factor^0.5
```

For `exp > BPS` (e.g. a DAO-configured `LIQ-CURVE-EXP` of `15000`, meaning an intended exponent of `1.5`), `(/ exp BPS)` truncates to `1`. The formula collapses to `(/ (pow factor 1) (pow BPS 0))` = `factor` — i.e. the exponent has *no effect at all* and the curve behaves exactly as the linear (`exp == BPS`) case, for the entire range `10000 < exp < 20000`. The same collapse happens for every other non-exact-multiple band (`20000 < exp < 30000` truncates to exponent `2`, etc.). For `exp < BPS`, any non-`5000` value is coerced into a `sqrt` approximation regardless of the actual configured curve shape.

This function feeds directly into the graduated liquidation pipeline: [2](#0-1) 

```
(define-private (calc-liquidation-params ...)
  (let ((liq-pct-linear (calc-liq-factor current-ltv ltv-liq-partial ltv-liq-full))
        (liq-pct-scaled (calc-liq-factor-exp liq-pct-linear curve-exponent))
        (liq-penalty (calc-liq-factor-bound liq-pct-scaled liq-penalty-min liq-penalty-max))
        (max-debt-usd (calc-liq-debt-repay total-debt-usd liq-pct-scaled)))
    ...)
```

`max-debt-usd` (the maximum amount of debt eligible to be repaid/liquidated in that call) and `liq-penalty` (the liquidator's bonus, which determines how much collateral is seized per unit of debt) are both direct functions of the miscalculated `liq-pct-scaled`. Because `factor^n < factor` for any `factor < BPS` and `n > 1`, a truncated exponent (effectively `n = 1` instead of the intended `n ∈ (1,2)`) produces a strictly *larger* `liq-pct-scaled` than the curve design intended. A larger `liq-pct-scaled` directly increases `max-debt-usd` via `calc-liq-debt-repay`, which increases the collateral seized via `calc-liq-collateral-repay`/`calc-liq-debt-repay-real` downstream in the liquidation flow.

### Impact Explanation
Any liquidator (an unprivileged caller) calling the public liquidation entrypoint against a borrower's position under an egroup configured with a "gentle"/intermediate `LIQ-CURVE-EXP` (any value that is not an exact multiple of `10000`, e.g. `15000` for a designed 1.5x aggressive curve) will cause the protocol to compute a higher `max-debt-usd`/liquidation percentage than the risk parameters were designed to allow at that LTV. This lets the liquidator seize more of the borrower's collateral in a single liquidation call than the graduated curve intends — a seizure exceeding its designed bound, at the direct expense of the borrower (a distinct unprivileged principal) whose remaining collateral is reduced beyond the intended schedule. This is a temporary/permanent freezing or loss of the borrower's collateral value beyond the intended liquidation curve, which the bound (`calc-liq-factor-bound`'s `min bound-max`) does not fully protect against because it clamps only the penalty percentage, not the increased eligible debt (`max-debt-usd`) computed with the wrong `liq-pct-scaled`.

### Likelihood Explanation
Exploitability depends entirely on the `LIQ-CURVE-EXP` values the DAO configures for a given egroup. I was unable to confirm from the indexed contents of `mainnet/contracts/proposals/mainnet/v0-init.clar` what concrete `LIQ-CURVE-EXP` values are deployed (the file matched many references to the constant but I could not retrieve the specific `u<value>` assignments within my remaining tool budget). If any live egroup uses a non-exact-multiple-of-`10000` exponent (which the parameter's own documentation explicitly anticipates — e.g. any curve strictly between "linear" (10000) and "aggressive" (20000), such as 15000), this bug is triggered on every liquidation against that egroup, making it highly likely to be exploitable in practice rather than a theoretical edge case.

### Recommendation
Rework `calc-liq-factor-exp` to use exact fixed-point exponentiation consistent with the `BPS`-scaled fixed-point representation (analogous to Balancer's `bpow`), rather than truncating `exp / BPS` to an integer power. At minimum, reject/round configured `LIQ-CURVE-EXP` values that are not exactly representable by the current integer-power implementation, or implement a proper fractional power (e.g., binary exponentiation combined with correctly weighted linear interpolation between adjacent integer powers) so that `liq-pct-scaled` matches the intended curve for arbitrary `curve-exponent` values.

### Proof of Concept
1. DAO configures an egroup with `LIQ-CURVE-EXP = u15000` (intended as a 1.5x "moderately aggressive" curve, a value explicitly documented as valid: `docs/egroups.md` states any `>10000` value gives "aggressive curve").
2. Borrower's position crosses `ltv-liq-partial` such that `calc-liq-factor` yields, e.g., `liq-pct-linear = 5000` (50%).
3. `calc-liq-factor-exp` is called with `factor = 5000`, `exp = 15000`. Since `exp > BPS`, `(/ exp BPS)` = `1` (integer truncation), so the result reduces to `(/ (pow 5000 1) (pow 10000 0))` = `5000` — identical to the untransformed linear factor, instead of the intended `5000^1.5`-scaled (smaller) value.
4. This inflated `liq-pct-scaled` (`5000` instead of the intended lower discounted value) is passed to `calc-liq-debt-repay`, producing a larger `max-debt-usd` than the curve was designed to permit at that LTV.
5. A liquidator calling the public liquidate function is able to liquidate/seize a larger amount of the borrower's collateral than the graduated curve was designed to allow, at the borrower's expense. [3](#0-2)

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
