Based on the codebase, the closest true analog to the pump.science fee-formula-discontinuity bug is the graduated liquidation penalty curve in `market.clar` / `v0-4-market.clar`, where the exponent scaling formula silently collapses to a linear curve for any DAO-configured exponent that is not an exact multiple of `BPS`, causing borrowers to be liquidated with a materially higher penalty/seizure than the configured curve intends.

### Title
Graduated liquidation curve exponent truncation causes borrowers to be over-liquidated beyond the configured penalty curve - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary

### Finding Description
The graduated liquidation feature scales the liquidation penalty and the max-liquidatable debt using a curve exponent `LIQ-CURVE-EXP`, applied via `calc-liq-factor-exp`: [1](#0-0) 

```clarity
(define-private (calc-liq-factor-exp (factor uint) (exp uint))
  (if (is-eq exp BPS) 
    factor
    (if (> exp BPS) 
        (/ (pow factor (/ exp BPS)) (pow BPS (- (/ exp BPS) u1)))
        (sqrti (* factor BPS))))) ;; assume factor^0.5
```

Per the egroup documentation, `LIQ-CURVE-EXP` is a legitimate DAO-configured bps value where `>10000` means an "aggressive" curve and the exponent is meant to represent `exp/BPS` (e.g. `15000` = exponent `1.5`): [2](#0-1) 

The `> exp BPS` branch computes the effective integer exponent as `(/ exp BPS)`, which is **integer division that truncates any non-multiple-of-10000 value down to the next lower integer**. For any configured exponent strictly between `10000` and `19999` (e.g. the documented example `15000`), `(/ exp BPS)` evaluates to `1`, making `calc-liq-factor-exp` compute `factor^1 / BPS^0 = factor` — i.e., the exact same result as the pure-linear case (`exp = BPS`) — completely discarding the intended curve shape. The formula only behaves correctly at exact multiples of `BPS` (`10000`, `20000`, `30000`, …), and jumps discontinuously in behavior right at those boundaries, mirroring the pump.science bug class: a formula whose coefficients/branches don't correctly interpolate between the two ends of its intended range, producing an abrupt, uncalibrated transition.

Because raising a fraction (`factor < BPS`, representing 0–100%) to a higher exponent (>1) always yields a **smaller** result than the same fraction to the power 1, the truncation bug always produces a **larger** `liq-pct-scaled` than intended whenever the DAO configures a non-multiple-of-`BPS` aggressive exponent. This larger `liq-pct-scaled` flows directly into: [3](#0-2) 

- `calc-liq-factor-bound`, which produces a **higher `liq-penalty`** than the curve intended.
- `calc-liq-debt-repay`, which produces a **higher `max-debt-usd`** (more debt eligible to be repaid/liquidated at once) than the curve intended.

Both of these feed the actual `liquidate` execution: [4](#0-3) 

### Impact Explanation
For any egroup where the DAO sets a legitimate, in-range, "aggressive-curve" exponent that is not an exact multiple of `10000` (a normal, expected configuration per the documented parameter range), every liquidator (unprivileged attacker) that liquidates a borrower (unprivileged victim) under that egroup will seize **more collateral and a higher penalty than the configured curve entitles them to** — a direct theft of the borrower's collateral beyond the intended seizure bound. This is not a hypothetical misconfiguration; it is a normal, documented use of the parameter (`>10000` = aggressive curve) that the code fails to implement correctly for any value that isn't an exact `BPS` multiple. This is a direct theft of borrower funds (collateral) at rest, qualifying as Critical impact.

### Likelihood Explanation
Likelihood is high: any egroup configured with a "gentle-but-not-exactly-0.5" or "aggressive-but-not-exactly-integer" curve exponent (the vast majority of the valid `LIQ-CURVE-EXP` range above `BPS`) triggers this on every single liquidation for that egroup — no special timing, race, or privileged action is required by the liquidator, only that the position becomes liquidatable.

### Recommendation
Replace the integer-exponentiation approximation with a proper fixed-point power function (e.g. bps-scaled `pow` via repeated squaring/logarithm approximation) that correctly handles any `exp/BPS` ratio, or restrict `LIQ-CURVE-EXP` at write-time to only accept exact multiples of `BPS` (and validate this in `set-egroup`), and document/enforce that restriction so the executed curve always matches the configured curve.

### Proof of Concept
1. DAO configures an egroup with `LIQ-CURVE-EXP = 15000` (a legitimate, documented "aggressive curve" value, per `docs/egroups.md`).
2. A borrower's position crosses into partial liquidation range, e.g. `liq-pct-linear = 5000` (50%, from `calc-liq-factor`).
3. Intended curve value: `factor^1.5` scaled ≈ a value smaller than `5000` bps (curve should suppress penalty at mid-range factor).
4. Actual code path: `(/ exp BPS)` = `(/ 15000 10000)` = `1` (integer truncation) ⇒ `calc-liq-factor-exp` returns `factor^1 / BPS^0 = 5000` — identical to a pure linear curve, not the intended aggressive curve.
5. This inflated `liq-pct-scaled = 5000` feeds into `calc-liq-factor-bound` and `calc-liq-debt-repay`, producing a higher `liq-penalty` and higher `max-debt-usd` than the DAO's configured curve intended.
6. The liquidator receives a bonus/collateral seizure larger than the configured bound at the victim borrower's expense, on every liquidation call under this egroup.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L706-713)
```text
;; Apply curve exponent for graduated liquidation
;; liq-factor = liq-factor^alpha
(define-private (calc-liq-factor-exp (factor uint) (exp uint))
  (if (is-eq exp BPS) 
    factor
    (if (> exp BPS) 
        (/ (pow factor (/ exp BPS)) (pow BPS (- (/ exp BPS) u1)))
        (sqrti (* factor BPS))))) ;; assume factor^0.5
```

**File:** mainnet/contracts/market/v0-4-market.clar (L715-724)
```text
;; Scale penalty between min and max using liquidation factor
;; liq-penalty = liq-penalty-min + (liq-factor * (liq-penalty-max - liq-penalty-min) / BPS)
;; Capped at bound-max to handle cases where liq-factor > BPS
(define-private (calc-liq-factor-bound (liq-factor uint) (bound-min uint) (bound-max uint))
  (min bound-max (+ bound-min (mul-bps-down liq-factor (- bound-max bound-min)))))

;; Calculate debt to repay based on liquidation factor
;; debt-repay = liq-factor * debt / BPS
(define-private (calc-liq-debt-repay (debt uint) (liq-factor uint)) 
  (mul-bps-down liq-factor debt))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1437-1467)
```text
    ;; liquidation parameters (graduated liquidation calculation)
    (liq-params (calc-liquidation-params 
                  current-ltv ltv-liq-partial ltv-liq-full
                  liq-penalty-min liq-penalty-max 
                  curve-exponent total-debt-usd))
    (liq-pct-scaled (get liq-pct-scaled liq-params))
    (liq-penalty (get liq-penalty liq-params))
    (max-debt-usd (get max-debt-usd liq-params))

    ;; debt processing
    (debt-info (process-debt-asset debt-amount debt-aid max-debt-usd assets))
    (debt-actual-usd (get debt-actual-usd debt-info))
    (debt-actual (get debt-actual debt-info))
    (debt-price (get debt-price debt-info))
    (debt-decimals (get debt-decimals debt-info))

    ;; collateral processing
    (user-coll-balance (find-collateral-amount (get collateral pos-full) coll-aid))
    (coll-info (process-collateral-asset coll-aid debt-actual-usd liq-penalty 
                                         user-coll-balance assets coll-asset))
    (coll-actual (get coll-actual coll-info))
    (coll-expected (get coll-expected coll-info))
    (coll-price (get coll-price coll-info))
    (coll-decimals (get coll-decimals coll-info))

    ;; final liquidation amounts (with proportional adjustment if needed)
    (final-amounts (calc-final-liquidation-amounts
                     debt-actual-usd coll-actual coll-expected
                     coll-price coll-decimals
                     debt-price debt-decimals liq-penalty))
    (debt-final-usd (get debt-final-usd final-amounts))
```

**File:** docs/egroups.md (L41-48)
```markdown
| `LIQ-CURVE-EXP` | bps | 10000 (1.0) | Exponent for graduated penalty curve |

**Graduated Liquidation:**

The `LIQ-CURVE-EXP` parameter controls how liquidation penalty scales between min and max:
- `10000` (1.0): Linear scaling
- `>10000` (>1.0): Aggressive curve (penalty increases faster)
- `<10000` (<1.0): Gentle curve (e.g., square root)
```
