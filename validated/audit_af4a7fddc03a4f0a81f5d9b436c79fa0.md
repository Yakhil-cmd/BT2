### Title
Liquidator can seize a borrower's entire collateral balance for a partial (attacker-minimized) debt repayment due to rounding in the "remaining debt" dust-sweep check - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
In `liquidate`, when a liquidator only partially repays a position's debt, the contract computes the leftover collateral (`coll-remaining`) and tries to determine whether that leftover is "dust" (i.e., worth less than the smallest unit of the debt token) before deciding whether to award the liquidator only the proportional `coll-final-raw` or to sweep the *entire* `user-coll-balance` to them. Because this dust-check itself goes through several rounding-down conversions (`normalize`, `div-bps-down`, `mul-div-down`), it can be made to report "zero remaining debt" even when `coll-remaining` still holds real value, letting a liquidator who repays only a minimal, self-chosen `debt-amount` walk away with the borrower's *full* collateral balance.

### Finding Description
`liquidate` computes a proportional collateral seizure from the requested `debt-amount`: [1](#0-0) 

It then computes what's left over and tries to decide if that leftover is negligible enough to just be swept to the liquidator instead of remaining stuck as unliquidatable dust: [2](#0-1) 

`remaining-debt-to-repay` is derived by converting `coll-remaining` back into USD, then into debt-token units, then into scaled debt units, through a chain of `div-bps-down` / `mul-div-down` / `mul-div-up` operations - each of which rounds down at least once. If the debt asset has few decimals relative to its price (the same low-decimals precision-loss class described in the referenced Aloe report), or if the liquidator deliberately chooses a `debt-amount` small enough that `coll-final-raw` is tiny (satisfying only the `> u0` check) and `coll-remaining` is consequently large but still converts to a `rem-debt-tokens` value that truncates to zero, `remaining-debt-to-repay` becomes `u0`. When that happens: [3](#0-2) 

`coll-final` is set to the *entire* `user-coll-balance`, not the proportional `coll-final-raw` that corresponds to the debt actually repaid (`debt-to-repay`). The only guards before execution are that the amounts are non-zero and meet the liquidator's own slippage floor: [4](#0-3) 

There is no check that `coll-final` is proportionate to `debt-to-repay` relative to the borrower's total debt - it directly transfers the full collateral balance to the liquidator (or their designated `collateral-receiver`): [5](#0-4) 

Because `debt-to-repay` was only a small fraction of the borrower's obligation, the borrower is left with debt but no collateral. If this asset was the borrower's only collateral (or all remaining collateral assets are likewise exhausted), the position is deemed to have `no-collateral-left` and the leftover debt is *socialized* onto vault depositors rather than the borrower who caused it: [6](#0-5) [7](#0-6) 

This is the same root cause as the referenced Aloe finding (M-10): rounding in the liquidation math lets a liquidator obtain collateral disproportionate to the debt they actually repaid, at the expense of the borrower and, ultimately, the vault's other depositors via bad-debt socialization.

### Impact Explanation
The borrower (victim, an unprivileged principal) loses their entire collateral balance to a liquidator who repaid only a minimal, attacker-chosen fraction of the outstanding debt - this is direct theft of user funds at rest (their locked collateral). The unrepaid remainder becomes bad debt that is socialized across vault suppliers, spreading the loss to a third, uninvolved party. Both outcomes fall within the Critical impact class ("direct theft of user funds at rest ... or protocol insolvency" via bad-debt socialization).

### Likelihood Explanation
The health check (`current-ltv >= ltv-liq-partial`) must first be true, so this requires a borrower whose position is already eligible for liquidation - a routine and common event. Given that, triggering the rounding condition only requires the attacker to submit a small, self-chosen `debt-amount` on a market/asset combination where the resulting `rem-debt-tokens` truncates to zero (favored by low debt-token decimals or by choosing a minimal `debt-amount`, since the leftover computation and the primary computation share the same rounding-down chain). Since `liquidate` is a fully public, unprivileged entry point, any bot can probe candidate positions/assets for this condition cheaply.

### Recommendation
- Bound `coll-final` by the borrower's proportional share corresponding to `debt-to-repay` relative to their total outstanding debt (i.e., never allow the "no remaining debt" dust-sweep branch to exceed a small, explicitly-capped absolute dust threshold rather than a value derived from the same rounding-prone conversion chain).
- Alternatively, require that the dust-sweep only trigger when `coll-remaining` itself (in token or USD terms, computed independently of the lossy multi-step conversion) is below an explicit minimum threshold, not merely when the derived `remaining-debt-to-repay` happens to round to zero.
- Add an invariant assertion that `coll-final <= coll-expected` (or a small epsilon above it) whenever `debt-to-repay < curr-scaled`'s full amount, preventing any partial repayment from ever sweeping full collateral.

### Proof of Concept
1. Borrower's position becomes liquidatable (`current-ltv >= ltv-liq-partial`) on a debt asset with low decimals relative to its price (or generally where `debt-price / 10^debt-decimals` is large).
2. Liquidator calls `liquidate` with a minimal `debt-amount` such that `debt-to-repay` from `scale-debt-for-liquidation` is the smallest positive value satisfying `(> debt-to-repay u0)`, and the correspondingly tiny `coll-final-raw`.
3. `coll-remaining = user-coll-balance - coll-final-raw` is computed; feeding it through `normalize` → `div-bps-down` → `mul-div-down` → `mul-div-up` truncates `remaining-debt-to-repay` to `u0` even though `coll-remaining` still represents real, non-dust collateral value.
4. `coll-final` is reassigned to the full `user-coll-balance`, `(> coll-final u0)` and `(>= coll-final min-collateral-expected)` pass trivially (liquidator sets a low `min-collateral-expected`), and `collateral-remove` transfers the borrower's entire collateral balance to the liquidator for a payment of only `debt-to-repay` (near-minimal debt).
5. The borrower is left with the remaining unrepaid debt and zero collateral; if this exhausts all their collateral assets, `no-collateral-left` triggers `socialize-debt-asset`, writing down the borrow index and spreading the loss to depositors in the affected vault.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1471-1486)
```text
    (curr-scaled (get-account-scaled-debt borrower debt-aid))
    (scaled-info (scale-debt-for-liquidation debt-final coll-actual curr-scaled debt-aid))
    (scaled-to-remove (get scaled-to-remove scaled-info))
    (debt-to-repay (get debt-to-repay scaled-info))
    (coll-final-raw (get coll-final scaled-info))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1488-1493)
```text
    (asserts! (not (is-liquidation-paused debt-aid)) ERR-LIQUIDATION-PAUSED)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    (asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1499-1512)
```text
    (let ((debt-updated (try! (contract-call? .v0-market-vault
                              debt-remove-scaled
                              borrower
                              scaled-to-remove
                              debt-aid)))
          ;; Collateral receiver defaults to liquidator if not specified
          (actual-receiver (match collateral-receiver recv recv liquidator))
          (coll-removed (try! (contract-call? .v0-market-vault
                              collateral-remove
                              borrower
                              coll-final
                              collateral-ft
                              coll-aid
                              actual-receiver)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1526-1530)
```text
          (no-collateral-left (and
                                (is-eq coll-removed u0)
                                (or
                                  (is-eq (len (get collateral pos-full)) u1)
                                  (and
```

**File:** local-testing/contracts/market/market.clar (L1557-1583)
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
