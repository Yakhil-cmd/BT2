### Title
Liquidation "dust-sweep" logic can seize a borrower's full collateral for an asset while repaying less debt than that collateral is worth, forcing bad-debt socialization onto suppliers - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
In `liquidate`, after the normal proportional debt/collateral calculation, the contract runs a second "leftover dust" pass that can bump `coll-final` up to the borrower's **entire** remaining balance of that collateral asset, without increasing `debt-to-repay` to match. This mirrors the reported class of bug: the value of assets seized can exceed the value of debt actually repaid because of a rounding-to-zero condition, and the excess uncollateralized debt is then socialized onto all suppliers of that vault.

### Finding Description
`scale-debt-for-liquidation` first computes the "proportional" repay/seize pair (`debt-to-repay`, `coll-final-raw`) from the liquidator-requested amount [1](#0-0) .

`liquidate` then computes what's left of the borrower's collateral balance for that asset (`coll-remaining`) and converts it to an equivalent debt amount (`remaining-debt-to-repay`), rounding the conversion **down** through `mul-div-down` into scaled units before rounding back up: [2](#0-1) 

If `remaining-debt-to-repay` rounds down to `u0`, the code sets `coll-final` to the borrower's **full** `user-coll-balance` for that asset — sweeping all the remaining collateral — while `debt-to-repay` (used in `vault-system-repay` and `debt-remove-scaled`) is **not** adjusted upward to compensate: [3](#0-2) 

The rounding-to-zero condition is: `rem-debt-tokens * INDEX-PRECISION < rem-borrow-index`, i.e. the leftover collateral's equivalent debt-token amount is smaller than `rem-borrow-index / INDEX-PRECISION`. `INDEX-PRECISION` is a fixed per-vault constant (`u1000000000000`, i.e. 1e12) [4](#0-3) , while `rem-borrow-index` grows unboundedly as interest accrues (the borrow index is not capped, and the protocol's IRM is documented elsewhere to permit extremely high APRs). As `rem-borrow-index` inflates relative to `INDEX-PRECISION`, the "dust" threshold that triggers the full-collateral sweep grows from genuinely negligible amounts into economically significant amounts of collateral.

When this triggers, the borrower's tracked debt for that asset is only reduced by `scaled-to-remove` (the pre-sweep proportional amount) via `debt-remove-scaled` [5](#0-4) , yet all of the borrower's collateral of that type has left the position. If this collateral asset was the borrower's only collateral (or all collateral), `no-collateral-left` becomes true and the remaining, now fully unbacked, debt is immediately socialized across all lenders of that debt vault via `socialize-debt-asset` [6](#0-5) .

This is structurally the same root cause as the external report: a rounding-down computation (`mul-div-down` into scaled/shares units) that decides "no more debt needs to be repaid" is used to justify seizing collateral whose value is not actually matched by the debt that was repaid.

### Impact Explanation
The victim is the borrower, whose collateral is seized for free relative to the debt actually cleared from their position, and — transitively — all suppliers of the debt vault, who absorb the resulting bad debt through `socialize-debt-asset`. This is a protocol-insolvency-class impact (bad debt socialized onto passive suppliers) driven purely by a rounding/threshold flaw in liquidation math, not by any oracle manipulation or privileged action.

### Likelihood Explanation
Exploitability requires the debt asset's borrow index to have inflated substantially relative to `INDEX-PRECISION` (1e12) so that the "remaining debt" conversion for a non-trivial amount of collateral rounds to zero scaled units. This is achievable if the asset has sustained very high borrow rates/utilization for long enough to compound the index by many orders of magnitude, which the interest-rate model does not appear to hard-cap. This makes the condition realistic under sustained high-utilization/high-rate market conditions rather than requiring any privileged or DAO action, though it needs meaningful index inflation to make the swept amount economically significant (versus true dust).

### Recommendation
Ensure `debt-to-repay`/`scaled-to-remove` is increased to match whenever `coll-final` is bumped up to `user-coll-balance` in the dust-sweep branch — i.e., recompute the scaled debt removed from the full seized collateral value (mirroring the external report's suggested fix of readjusting the repaid-asset side up rather than silently leaving collateral seizure unmatched by debt repayment). Alternatively, cap the dust-sweep threshold to an absolute, asset-independent small amount instead of a value that scales with the (unbounded) borrow index.

### Proof of Concept
1. Over time, force asset `X`'s vault into sustained high utilization so its borrow `index` compounds far above `INDEX-PRECISION` (1e12), e.g. by repeatedly borrowing near the debt cap.
2. Once `rem-borrow-index / INDEX-PRECISION` corresponds to a materially large amount of token `X` (no longer "dust"), find/create a borrower whose position uses `X` as sole collateral and is liquidatable.
3. Liquidator calls `liquidate` with a `debt-amount` sized so that after the proportional calc, `coll-remaining` for asset `X` converts (via `mul-div-down`) to `rem-scaled = 0`.
4. `coll-final` is set to `user-coll-balance` (full collateral swept) at [7](#0-6) , but `debt-to-repay`/`scaled-to-remove` remain based on the smaller proportional amount.
5. `no-collateral-left` becomes true, triggering `socialize-debt-asset`, which writes off the remaining unbacked debt against all suppliers of the debt vault [6](#0-5) , while the liquidator walked away with collateral worth more than the debt they repaid.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L858-877)
```text
(define-private (scale-debt-for-liquidation
  (debt-final uint)
  (coll-actual uint)
  (curr-scaled uint)
  (asset-id uint))
  (let (;; convert debt amount to scaled units for storage
        (borrow-index (get index (unwrap-panic (get-cached-indexes asset-id))))
        (scaled-debt (mul-div-down debt-final INDEX-PRECISION borrow-index))
        ;; cap at current debt (prevent over-repayment)
        (scaled-to-remove (if (> scaled-debt curr-scaled) curr-scaled scaled-debt))
        (debt-to-repay (mul-div-up scaled-to-remove borrow-index INDEX-PRECISION))
        ;; If debt was capped, scale collateral proportionally
        (coll-final (if (< scaled-to-remove scaled-debt)
                        (mul-div-down coll-actual scaled-to-remove scaled-debt)
                        coll-actual)))
    {
      scaled-to-remove: scaled-to-remove,
      debt-to-repay: debt-to-repay,
      coll-final: coll-final
    }))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1495-1512)
```text
    ;; execute liquidation
    (try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))

    ;; update obligations and socialize bad debt
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

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L27-27)
```text
(define-constant INDEX-PRECISION u1000000000000)  ;; 1e12 for index calculations
```
