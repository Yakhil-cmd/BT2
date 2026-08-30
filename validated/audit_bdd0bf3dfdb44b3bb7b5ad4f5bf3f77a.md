### Title
Premature bad-debt socialization can write off debt while un-seized collateral still remains on the position - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`liquidate()` decides whether to fully socialize (write off) a borrower's remaining debt based on a rounded-down estimate of how much debt the borrower's *other* collateral could still cover (`other-debt-repayable`). When that estimate floors to zero due to integer-division rounding — even though the borrower still holds non-zero collateral in another asset — the function treats the position as fully collateral-exhausted and writes the entire remaining debt off onto the debt-asset supplier pool via `socialize-debt-asset`, while the borrower keeps the un-seized collateral.

### Finding Description
In `liquidate()`, after seizing the targeted collateral asset, the contract computes whether any other collateral remains that could still cover debt: [1](#0-0) 

`other-coll-usd` is the USD value of any *other* collateral asset(s) still on the position. `other-debt-repayable` converts that USD value into a debt-token amount using `div-bps-down` and `mul-div-down`, both of which round **down**. If the borrower's remaining collateral in the other asset is small (dust) relative to the debt asset's decimals/price, `other-debt-repayable` can round to `u0` even though `other-coll-usd` (and the underlying collateral) is strictly greater than zero.

`no-collateral-left` is then computed as `true` whenever the just-liquidated asset was fully drained (`coll-removed == u0`) **and** (the position originally had only one collateral type, **or** `other-debt-repayable == u0`): [2](#0-1) 

When `no-collateral-left` is `true`, the contract socializes (writes off) **all** of the borrower's remaining debt across all debt assets via `fold socialize-debt-asset`, calling `vault-socialize-debt` (which write-downs the global index, spreading the loss across all suppliers of that debt asset) and then zeroes the borrower's debt entry: [3](#0-2) 

This is the same root-cause pattern as the referenced Papr `PaprController` finding: a heuristic ("is this the last collateral / is there really nothing left to recover") is evaluated using an incomplete/roundable signal, and when it wrongly concludes "nothing more can be recovered," it writes off debt (there: `_reduceDebtWithoutBurn`; here: `socialize-debt-asset`) even though value that should have covered the shortfall (there: NFT auction proceeds; here: the borrower's other, un-seized collateral) still exists and is later retained by the borrower for free, exactly as Backed's own maintainer confirmed the fix must also check "whether there is another auction ongoing" — here the analogous check (`other-debt-repayable == u0`) is unreliable due to rounding.

### Impact Explanation
The victims are the other suppliers of the debt asset pool: `vault-socialize-debt` writes down the shared borrow/supply index for that asset, meaning **all depositors of that debt asset** absorb the unrecovered debt, even though the borrower still holds recoverable, non-zero collateral in a different asset that was never seized or otherwise repaid. The borrower keeps that leftover collateral (withdrawable normally once their debt shows as zero) at zero cost. This is a direct write to a shared state (the global borrow index / supplier pool) triggered by one unprivileged caller (the liquidator) that harms a different set of unprivileged principals (the debt-asset suppliers), and is not ordinary shared-pool economics — it is a rounding-induced incorrect early write-off of debt while collateral value remains on-chain. This matches the Critical impact class of protocol insolvency (bad debt improperly socialized onto suppliers) and effectively enables theft of that value by the borrower.

### Likelihood Explanation
This requires a borrower position with at least two different collateral asset types where one asset is large/dominant and the other is a small ("dust") remainder, and a liquidator (who need not be malicious — any liquidator triggering `liquidate()` on the dominant asset first, which is the natural strategy since it is the most valuable seizeable collateral) fully draining that dominant asset in one call. Given `mul-div-down`/`div-bps-down` truncation, this can be reached whenever the second asset's USD value, once divided by `(BPS + liq-penalty-max)` and converted to debt-token units, floors to zero — plausible for low-decimal or low-priced secondary collateral assets, or simply very small leftover balances. No privileged access or DAO action is needed.

### Recommendation
Do not rely solely on a rounded-to-zero `other-debt-repayable` value to determine `no-collateral-left`. Instead, check directly whether the borrower has any non-zero collateral balance remaining in any other collateral asset (i.e., inspect the actual collateral map/balances, not a derived, rounding-lossy USD/debt-token conversion) before triggering full debt socialization. Only socialize debt once all real collateral balances backing that debt are provably exhausted.

### Proof of Concept
1. Borrower deposits a large amount of collateral asset A (e.g. sBTC) and a tiny "dust" amount of collateral asset B (e.g. STX), then borrows debt asset D up to the liquidation threshold.
2. Price of A drops so the position enters the full-liquidation zone (`current-ltv >= ltv-liq-full`), making `max-debt-usd` cover (approximately) all outstanding debt.
3. A liquidator calls `liquidate(borrower, A, D, debt-amount, ...)`. Because the borrower's balance of A is fully consumed (`coll-final == user-coll-balance` of A), `coll-removed` (the balance of A remaining, returned by `collateral-remove`) becomes `u0`.
4. `other-coll-usd` is computed as B's USD value (non-zero dust), but `other-debt-repayable` — derived via `div-bps-down` then `mul-div-down` — rounds down to `u0` because B's dust value is too small relative to D's price/decimals.
5. `no-collateral-left` evaluates to `true`; `bad-debt-socialized` triggers, calling `socialize-debt-asset` for the borrower's remaining debt in D, which zeroes the borrower's debt via `debt-remove-scaled` and write-downs the global index in `vault-socialize-debt`, spreading the loss to all D suppliers.
6. Borrower's debt in D is now `0`; borrower's collateral B balance is untouched and can subsequently be withdrawn for free via the normal withdraw path, since the position no longer appears unhealthy. [4](#0-3)

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1514-1560)
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
