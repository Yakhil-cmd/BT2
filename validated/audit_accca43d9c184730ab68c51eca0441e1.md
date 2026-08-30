### Title
Rounding-down of `other-debt-repayable` causes premature bad-debt socialization to suppliers while borrower keeps unliquidated collateral dust - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
In `liquidate`, the decision to write off a borrower's remaining debt as bad debt (socialized across all vault suppliers) instead of first recovering it from the borrower's other collateral is gated by `other-debt-repayable`, a value computed entirely with floor-rounding helpers (`div-bps-down`, `mul-div-down`). When the borrower's non-seized ("other") collateral has non-zero USD value but that value floors to zero debt tokens during the conversion, the contract wrongly concludes there is "no collateral left" and socializes the entire remaining debt to suppliers, leaving the borrower's residual collateral untouched and unseized.

### Finding Description
`liquidate` computes, after seizing the targeted collateral asset, whether the borrower's other (non-seized) collateral could still repay some debt: [1](#0-0) 

```
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

Every intermediate step (`div-bps-down`, `mul-div-down` twice) rounds down. Even though `other-coll-usd > 0` (i.e. the borrower genuinely still has some collateral value in other assets), the chained floor operations can drive `other-tokens`/`other-scaled` to `0`, so `other-debt-repayable` evaluates to `u0`.

That result feeds directly into the `no-collateral-left` flag: [2](#0-1) 

```
(no-collateral-left (and
                      (is-eq coll-removed u0)
                      (or
                        (is-eq (len (get collateral pos-full)) u1)
                        (and
                          (is-eq (len (get collateral pos-full)) (len (get collateral position)))
                          (is-eq other-debt-repayable u0)))))
```

When `no-collateral-left` is true, the remaining debt for `debt-aid` is stripped and passed to `socialize-debt-asset`, which calls `vault-socialize-debt`, writing the loss down across all suppliers of that debt vault, and removes the scaled debt from the borrower's obligation: [3](#0-2) 

Critically, this bad-debt socialization path only removes debt — it never seizes the borrower's remaining "other" collateral. The borrower is left holding that collateral for free, while the debt tied to it is erased from the suppliers' books instead of being recovered.

### Impact Explanation
This lands in the explicitly-permitted analog category "a socialization charged to all suppliers." The victims are the vault's liquidity suppliers (an unprivileged group distinct from the liquidator and the borrower), whose deposited principal absorbs a write-down that the code itself computed was avoidable (`other-coll-usd > 0`), purely due to the floor-rounding chain understating the recoverable amount. The borrower is the unintended beneficiary, keeping the un-seized collateral debt-free. The magnitude of the rounding error is bounded by roughly the USD value of a single debt-token unit (via `debt-price`), which for high-value debt assets (e.g., BTC-denominated debt) can represent a materially non-trivial amount, not merely negligible dust — this constitutes an insolvency-style loss socialized onto suppliers, i.e. permanent loss of supplied funds that should have been recoverable from the borrower's collateral.

### Likelihood Explanation
This triggers automatically inside the ordinary `liquidate` public function whenever a borrower holds multiple collateral types and the collateral being seized in a given call represents effectively all of the "primary" recoverable value while a small remainder sits in another collateral asset with a value that floors to zero debt-tokens once converted through `div-bps-down`/`mul-div-down`/`mul-div-down` for the specific debt asset's decimals/price. No malicious coordination is required — it is a deterministic consequence of a normal liquidation call by any liquidator against a multi-collateral, near-fully-liquidated position; the more valuable per-unit the debt asset, the more likely a non-trivial "other" collateral remainder floors to zero repayable debt tokens.

### Recommendation
Round `other-debt-repayable` up (ceiling) rather than down at each conversion step (`div-bps-up`/`mul-div-up` consistently), so that any strictly-positive `other-coll-usd` maps to at least `1` in `other-debt-repayable`. This prevents `no-collateral-left` from being incorrectly set to `true` while the borrower still holds unseized, USD-valued collateral, ensuring the code either attempts to seize/recover from that collateral before falling back to supplier-side socialization, or at minimum does not silently write off debt that overlapping collateral could partially cover.

### Proof of Concept
Conceptual PoC (Clarity-level, since this requires simulating a full market position, not a simple unit test snippet found in the index):
1. Borrower deposits two collateral assets: a small amount of Asset X (e.g. sBTC) sized such that its USD value, after subtracting the seized asset's value, is small but non-zero, and takes on debt in a high-per-unit-value debt asset (e.g. BTC-denominated debt) such that `other-coll-usd / debt-price` floors to `0` tokens once passed through `div-bps-down` and `mul-div-down` in `other-debt-repayable`.
2. Borrower's LTV crosses into the liquidation zone.
3. Liquidator calls `liquidate` targeting the primary/large collateral asset, fully seizing it (`coll-removed` becomes non-zero relative to `user-coll-balance`, i.e., `coll-final-raw == user-coll-balance` for that asset), while the secondary Asset X collateral remains in the position.
4. Because `other-coll-usd > 0` but `other-debt-repayable` computes to `0` via the floor chain, `no-collateral-left` evaluates `true`.
5. The remaining debt is stripped and socialized via `socialize-debt-asset` → `vault-socialize-debt`, decreasing supplier-facing yield/principal, while the borrower's Asset X collateral remains fully intact and unseized in their position.
6. Compare: without the rounding bug (using ceiling conversion), `other-debt-repayable` would be non-zero, `no-collateral-left` would be `false`, and the debt would not be socialized to suppliers at this step — leaving Asset X available for a subsequent liquidation call to actually recover value for suppliers instead of writing it off. [4](#0-3)

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
