### Title
Liquidation reverts entirely when bad-debt socialization encounters a zero scaled amount, blocking liquidation of unhealthy positions - (File: `mainnet/contracts/market/v0-4-market.clar`, `mainnet/contracts/vault/v0-vault-*.clar`)

### Summary
The `liquidate` function in `v0-4-market.clar` performs bad-debt socialization by folding over the borrower's remaining debt assets and calling each vault's `socialize-debt` function. The vault's `socialize-debt` unconditionally reverts with `ERR-AMOUNT-ZERO` if the `scaled-amount` argument is zero, mirroring the reported "reduce reverts on zero amount" bug class. If any debt entry folded into the socialization step ends up with a zero scaled amount, the entire `liquidate` transaction reverts via the `ERR-BAD-DEBT-SOCIALIZATION-FAILED` assertion, preventing liquidation of an insolvent position, which harms all depositors sharing that vault's pool, not just the liquidator who submitted the transaction.

### Finding Description
`liquidate` computes `no-collateral-left` and, when true, builds `fresh-debt-list` from the borrower's other outstanding debts and folds `socialize-debt-asset` over it to write off bad debt: [1](#0-0) 

Each fold iteration calls the corresponding vault's `socialize-debt`, which asserts the scaled amount is non-zero before proceeding: [2](#0-1) 

Back in `liquidate`, the fold's aggregate `success` flag is asserted, so any failure inside `socialize-debt-asset` (including one caused by a zero-amount revert bubbling up from the vault) aborts the whole liquidation call: [3](#0-2) 

This is structurally the same root cause as the reported issue: a downstream "reduce/decrement" style function (`socialize-debt`) unconditionally rejects a zero amount, and a caller-facing resolution/settlement flow (`liquidate`) can legitimately produce a zero amount for one of the items it iterates over, causing the entire operation to revert instead of completing.

### Impact Explanation
Unlike the auction bug (where only the caller/auctioneer is inconvenienced), here the victims are the passive lenders/depositors in the affected vaults and the protocol itself: an under-collateralized borrower with `no-collateral-left` cannot be liquidated and bad debt cannot be socialized while the zero-amount condition persists, leaving insolvent debt on the books and blocking liquidators from cleaning up the position. This is a shared-pool harm (depositors bear undercollateralized/bad debt that cannot be written off) distinct from ordinary shared-pool economics, since it stems from an unexpected revert bug rather than intended risk-sharing. This falls under temporary freezing of funds / protocol insolvency risk for the affected vault's depositors.

### Likelihood Explanation
Likelihood is low-to-moderate and depends on whether a debt entry in `fresh-debt-list` can realistically end up with a zero `scaled` value at the point `socialize-debt` is invoked. The liquidate function already filters out the currently-liquidated asset when its remaining debt is zero, which shows the codebase is aware zero-debt entries can occur; whether an equivalent zero-scaled stale entry can appear among the *other* debt assets of a multi-asset position (e.g., through rounding in `debt-remove-scaled`/accrual paths) was not confirmed with certainty from the code inspected.

### Recommendation
- Short term: make `socialize-debt` (and any other balance-reduction function called in a fold/loop over multiple assets) a no-op that returns `(ok true)` when `scaled-amount` is `0`, instead of reverting, so that liquidation of the rest of the position can complete.
- Long term: audit all "reduce/deduct/burn zero" assertions used inside multi-step or folded operations (`liquidate`, `liquidate-multi`, bad-debt socialization) to ensure a zero-value item can never abort an otherwise-valid batch operation; add fuzz/property tests exercising zero-amount edge cases in these shared flows.

### Proof of Concept
1. Borrower has multiple debt positions across several vaults; one debt asset is liquidated fully via `liquidate`, leaving `no-collateral-left = true` and triggering socialization of the borrower's remaining debts via the `fresh-debt-list` fold.
2. If any remaining debt entry in that list has (or can be driven to) a zero `scaled` value, `socialize-debt-asset` calls the vault's `socialize-debt` with `scaled-amount = 0`.
3. `v0-vault-usdh.clar`'s `socialize-debt` executes `(asserts! (> scaled-amount u0) ERR-AMOUNT-ZERO)` [4](#0-3)  and reverts.
4. The fold's `success` flag becomes false, the outer `(asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)` in `v0-4-market.clar` fires [5](#0-4) , and the entire `liquidate` call reverts — leaving the insolvent position unliquidated and unsocialized, to the detriment of the vault's depositors.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1534-1558)
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
```

**File:** mainnet/contracts/vault/v0-vault-usdh.clar (L942-964)
```text
(define-public (socialize-debt (scaled-amount uint))
  (let ((scaled-principal (var-get principal-scaled))
        (borrowed (var-get total-borrowed))
        (idx (var-get index))
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
```
