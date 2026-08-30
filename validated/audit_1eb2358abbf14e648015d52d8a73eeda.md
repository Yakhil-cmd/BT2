## Analog Found

### Title
Rounding in the "other collateral remaining" check during `liquidate` can trigger premature bad-debt socialization onto all lenders - (File: `local-testing/contracts/market/market.clar`, mirrored in `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar`'s `liquidate` function decides whether a borrower's position has "no collateral left" (and therefore whether to socialize the remaining debt across *all* suppliers of the debt vault) by converting the USD value of the borrower's *other* (non-liquidated) collateral into a debt-token amount through a chain of down-rounding divisions. When that residual collateral value is small ("dust"), every division in the chain rounds to zero, so the code concludes the borrower has effectively zero recoverable value left even though a nonzero collateral balance still exists on-chain. This causes bad-debt socialization to fire earlier/harder than warranted, permanently reducing the vault's `lindex` (and thus the value of every zToken holder's shares) instead of leaving the dust collateral available for later recovery.

### Finding Description
In `liquidate`, after seizing collateral of the targeted `coll-aid`, the contract estimates how much debt could still be repaid from the borrower's *other* collateral assets: [1](#0-0) 

`other-coll-usd` is the USD value of collateral not covered by the liquidated asset. When this is nonzero but small, the subsequent chain `div-bps-down` → `mul-div-down` (token conversion) → `mul-div-down` (scaled-debt conversion) → `mul-div-up` can all resolve to `u0`, because each intermediate step rounds down before the final rounds-up step is applied to an already-zeroed value. The result, `other-debt-repayable`, becomes `0` even though `other-coll-usd` was not zero.

This zero value feeds directly into the decision to treat the position as having no collateral left: [2](#0-1) 

When `no-collateral-left` incorrectly evaluates to `true`, the contract immediately runs bad-debt socialization on the borrower's remaining debt, writing down the vault's `lindex` for every existing supplier of that debt asset: [3](#0-2) [4](#0-3) 

The `lindex` write-down directly reduces `total-assets`/share value for every zToken holder of that vault, socializing a loss that (per the design intent visible in the "avoid rounding" comment at line 912) was only supposed to be socialized when collateral is truly exhausted.

### Impact Explanation
The victims are the vault's unprivileged suppliers (zToken holders), who did not participate in the liquidation transaction at all. The attacker/trigger is the liquidator (or the natural sequence of a partial liquidation on a multi-collateral borrower), who does not need to be malicious — merely liquidating a position whose other collateral happens to leave USD dust below the rounding threshold triggers this path. Before the liquidator's transaction, suppliers' zTokens are backed by the full, unwritten-down `lindex`. After the transaction, `lindex` is written down based on the borrower's *entire remaining debt* being socialized, even though a nonzero (but rounding-dust) collateral balance for that borrower still exists and could otherwise have been recovered in a later liquidation or repay. This is a permanent loss/freezing of unclaimed yield for the vault's lenders, landing in the in-scope **High** impact class ("temporary/permanent freezing of unclaimed yield ... socialization charged to all suppliers").

### Likelihood Explanation
This requires a borrower with multiple collateral assets where a partial liquidation leaves an "other collateral" USD remainder small enough that the multi-step down-rounding chain (`div-bps-down` → two `mul-div-down` conversions) collapses to zero before the final `mul-div-up`. Given six decimals-precision assets and BPS-scale liquidation penalties, dust remainders in the sub-cent range are plausible on low-decimal or low-priced collateral, making this reachable in ordinary liquidation flows rather than requiring an adversarial setup.

### Recommendation
Do not rely on the rounded-to-token `other-debt-repayable` value alone to decide `no-collateral-left`. Instead, compare `other-coll-usd` directly against a USD-denominated zero/dust threshold (or against zero without intermediate down-rounding conversions), or require that the underlying token collateral balance for other assets be checked directly (e.g., via `find-collateral-amount`) before concluding no collateral remains, so that genuine residual balances are never treated as fully exhausted due to compounding rounding.

### Proof of Concept
1. Borrower has two collateral assets: `coll-aid` (large balance, gets partially liquidated) and a second asset with a small remaining USD value after price appreciation of the primary collateral (dust, e.g. worth a fraction of a cent given `debt-decimals`/`coll-decimals` and current prices).
2. Liquidator calls `liquidate` against `coll-aid`. `coll-final` fully consumes the target collateral (`coll-removed` becomes the full amount) so the length/coll-removed branch condition is satisfied.
3. `other-coll-usd` (from the second collateral asset) is computed nonzero but small enough that `div-bps-down` → token conversion → scaled conversion all round to zero, yielding `other-debt-repayable = u0`.
4. `no-collateral-left` evaluates `true`, `socialize-debt-asset` runs over the borrower's remaining debt, and `vault-socialize-debt` writes down `lindex` in the debt vault contract, reducing the value of every outstanding zToken for that asset — even though the borrower's second collateral asset still has a nonzero on-chain balance that was never seized or accounted for.

### Citations

**File:** local-testing/contracts/market/market.clar (L901-925)
```text
(define-private (socialize-debt-asset
                (debt-entry { aid: uint, scaled: uint })
                (acc { borrower: principal, success: bool }))
  ;; Early return if previous socialization failed
  (if (not (get success acc))
      acc
      (let ((borrower (get borrower acc))
            (failed-status { borrower: borrower, success: false })
            (asset-id (get aid debt-entry))
            (scaled-debt (get scaled debt-entry)))

            ;; Socialize in vault - pass scaled directly to avoid rounding
            (unwrap! (vault-socialize-debt asset-id scaled-debt) failed-status)
            ;; Refresh cache with new indexes post-write-down (lindex decreased)
            (map-set index-cache
                     { timestamp: stacks-block-time, aid: asset-id }
                     (unwrap! (vault-accrue asset-id) failed-status))
            ;; Remove from obligation
            (unwrap! (contract-call? .market-vault
                                      debt-remove-scaled
                                      borrower
                                      scaled-debt
                                      asset-id) failed-status)
          acc)
        ))
```

**File:** local-testing/contracts/market/market.clar (L1537-1548)
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
```

**File:** local-testing/contracts/market/market.clar (L1549-1555)
```text
          (no-collateral-left (and
                                (is-eq coll-removed u0)
                                (or
                                  (is-eq (len (get collateral pos-full)) u1)
                                  (and
                                    (is-eq (len (get collateral pos-full)) (len (get collateral position)))
                                    (is-eq other-debt-repayable u0))))))
```

**File:** local-testing/contracts/vault/vault-stx.clar (L944-970)
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

    (print {
      action: "socialize-debt",
      caller: contract-caller,
```
