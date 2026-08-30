### Title
Dust-sized positions can accrue unprofitable-to-liquidate bad debt that is socialized onto all vault suppliers - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`v0-4-market.clar` allows opening a borrow position of any size (no minimum debt/collateral floor is enforced anywhere in the contract), while the liquidation reward is a *dynamic* penalty that ramps from `LIQ-PENALTY-MIN` (as low as ~1%) at the partial-liquidation threshold up to `LIQ-PENALTY-MAX` only once the position approaches full liquidation. For a dust-sized position, the absolute dollar reward at the low end of this curve can be smaller than the on-chain gas cost of calling `liquidate`, so no rational liquidator will act. The position is left to decay until it has zero collateral, at which point the market forcibly writes the unrecovered debt off via `socialize-debt`, which reduces `lindex` for every depositor in that vault - an unprivileged third party bearing the loss of a position they never interacted with.

### Finding Description
`liquidate` computes a graduated penalty `liq-penalty` scaled between `liq-penalty-min` and `liq-penalty-max` based on how unhealthy the position is: [1](#0-0) 

For a position that has just crossed `LTV-LIQ-PARTIAL`, `liq-pct-scaled` is near 0, so `liq-penalty` is near `liq-penalty-min` (e.g. 1%). Liquidator profit is `debt-repaid * liq-penalty`, computed in `calc-liq-collateral-repay`: [2](#0-1) 

Because there is no minimum position size check in the market contract's borrow/deposit paths (confirmed by an exhaustive search finding no `MIN-BORROW`, `MIN-DEPOSIT`, or `ERR-AMOUNT-TOO-SMALL` guard anywhere in the codebase), a position can be opened with debt worth only a few dollars. At a 1% penalty, liquidating a $5 debt position yields $0.05 - far below the gas cost of the `liquidate` transaction (which does substantial computation: price resolution, accrual, egroup lookup, graduated liquidation math, vault calls). No liquidator bot will execute this trade.

Left unliquidated, the position's debt continues to accrue interest while its collateral value can keep falling, eventually reaching the point where `no-collateral-left` becomes true and the market invokes bad-debt socialization: [3](#0-2) 

This calls `socialize-debt-asset`, which ultimately calls the per-vault `socialize-debt` function, directly writing down the shared `lindex` (liquidity index) that determines every depositor's redeemable balance: [4](#0-3) 

This is a direct write to shared state (`lindex`) consumed by all suppliers of that vault, primed entirely by the unliquidated borrower's dust position - the exact "socialization charged to all suppliers" pattern.

### Impact Explanation
Without an attacker/negligent-liquidator intervention, a dust position that turns underwater and cannot be economically liquidated leaves depositors' funds intact until the market operator manually intervenes (as the original DYAD team acknowledged doing themselves). With the bug, if the position is left unliquidated because it is unprofitable, when eventually forced into `no-collateral-left` bad-debt socialization, `lindex` is reduced for the *entire* pool of that debt asset, permanently reducing the redeemable balance of all lenders in that vault - not just the delinquent borrower. This is a permanent loss/freezing of supplier funds (their yield-bearing balance is haircut) caused by a position size that was never gated, and at scale (many dust positions accumulating bad debt across market downturns) it degrades protocol solvency for that vault. This lands on the Impact class of permanent freezing/loss of supplier funds via socialization.

### Likelihood Explanation
Likelihood is moderate: opening a small borrow position requires no special privilege and costs only the price of a small deposit; the liquidation penalty curve genuinely gives near-zero absolute reward at the low end for small principals, and Stacks gas costs are non-trivial for the multi-step `liquidate` call (accrual, egroup, oracle resolution, vault calls). During periods of network congestion or when a specific asset's price is volatile, many small positions could simultaneously become uneconomical to liquidate, converting to bad debt that must be socialized.

### Recommendation
Enforce a minimum USD-denominated debt (and/or minimum collateral) size at `borrow` time, below which new debt cannot be opened, similar in spirit to the DYAD team's acknowledged mitigation. Alternatively, guarantee a minimum absolute (not just percentage-based) liquidator reward, or allow permissionless "dust liquidation" that can be batched/subsidized so gas costs are amortized across multiple small positions before they degrade into bad debt requiring socialization.

### Proof of Concept
1. Borrower opens a position with debt near the market's smallest allowed unit (no minimum is enforced) and initial LTV just under `LTV-BORROW`.
2. Collateral price drops so `current-ltv` crosses `LTV-LIQ-PARTIAL`; `calc-liquidation-params` produces `liq-penalty` near `liq-penalty-min` (e.g., 1%) via `calc-liq-factor-bound`.
3. A liquidator calling `liquidate` would earn `debt-repay * 1%` in collateral bonus, which for a $5-$50 debt position is a few cents to a few dollars - less than the transaction's gas cost.
4. No liquidator calls `liquidate`; collateral price continues falling while debt accrues interest via `accrue-user-debts`.
5. Once collateral value reaches zero relative to debt, the position satisfies `no-collateral-left` in `liquidate`'s post-processing block, triggering `socialize-debt-asset` → vault `socialize-debt`, which reduces `lindex` for the entire vault: [5](#0-4) 
6. All depositors in that vault see their redeemable balance permanently reduced, despite never interacting with the delinquent borrower's position.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L715-734)
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

;; Calculate collateral to seize (includes liquidator bonus)
;; collateral-repay = debt-repay * (BPS + liq-penalty) / BPS
(define-private (calc-liq-collateral-repay (debt-repay uint) (liq-penalty uint)) 
  (mul-bps-down debt-repay (+ BPS liq-penalty)))

;; Calculate actual debt repayment when collateral is capped
;; debt-repay-real = (collateral-amount-usd * BPS) / (BPS + liq-penalty)
(define-private (calc-liq-debt-repay-real (collateral-amount-usd uint) (liq-penalty uint)) 
  (div-bps-down collateral-amount-usd (+ BPS liq-penalty)))
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

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L946-968)
```text
        (current-assets (var-get assets))
        (current-lindex (var-get lindex))
        (old-total-assets (total-assets))
        (debt-reduction (mul-div-down scaled-amount idx INDEX-PRECISION))
        (principal-reduction (if (> scaled-principal u0)
                                (mul-div-down scaled-amount borrowed scaled-principal)
                                u0))
        ;; Write down lindex proportionally to loss in total-assets
        (new-lindex (if (and (> old-total-assets u0) (> old-total-assets debt-reduction))
                       (mul-div-down current-lindex (- old-total-assets debt-reduction) old-total-assets)
                       u0)))

    (try! (check-caller-auth))
    (asserts! (> scaled-amount u0) ERR-AMOUNT-ZERO)

    (var-set lindex new-lindex)
    (var-set principal-scaled (if (> scaled-principal scaled-amount) (- scaled-principal scaled-amount) u0))
    (var-set total-borrowed (if (> borrowed principal-reduction) (- borrowed principal-reduction) u0))
    (var-set assets (if (> current-assets principal-reduction) (- current-assets principal-reduction) u0))

    (print {
      action: "socialize-debt",
      caller: contract-caller,
```
