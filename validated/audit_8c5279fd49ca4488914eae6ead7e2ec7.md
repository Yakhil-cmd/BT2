Based on the code reviewed, the described attack path does not hold up.

`socialize-debt-asset` in `market.clar`/`v0-4-market.clar` is a `define-private` function that can only be invoked from inside `liquidate` itself, via the single `fold socialize-debt-asset fresh-debt-list ...` call gated by `no-collateral-left`. There is no separate public entry point that a market participant (or the liquidator in a follow-up transaction/block) can call directly to trigger socialization for an isolated debt leg. [1](#0-0)  This already rules out the "Block N+1, market calls socialize-debt-asset for the STX leg" step in the described sequence — there is no independent call surface for that.

More importantly, the `liquidate` function's bad-debt gate is explicitly designed to net against a borrower's *other* collateral before allowing socialization. Within the same transaction:
- `target-coll-full-usd` computes the USD value of the borrower's full balance in the collateral asset being liquidated.
- `other-coll-usd` is `total-collateral-usd - target-coll-full-usd`, i.e. the USD value of every *other* collateral asset the borrower still holds (e.g., the non-STX leg in the scenario).
- `other-debt-repayable` converts that other-collateral value into an equivalent scaled-debt-repayable amount.
- `no-collateral-left` is only `true` when `coll-removed` (remaining balance of the liquidated collateral) is `0` **and** either the borrower has just one collateral asset total, or (same collateral-asset count and) `other-debt-repayable` is `0`. [2](#0-1) 

This means if attacker A's position has a second collateral asset (e.g. sBTC) with meaningful USD value still outstanding after the liquidator seizes the STX-side collateral, `other-debt-repayable` will be non-zero, `no-collateral-left` evaluates to `false`, and the `bad-debt-socialized` branch (which calls `socialize-debt-asset` → `vault-socialize-debt` → cuts `lindex`) is skipped entirely. [3](#0-2)  Socialization only fires when the borrower genuinely has no residual collateral value anywhere in the position to cover the remaining debt — i.e., when the "other asset value already recovered the debt" premise of the question is false by construction. The invariant the question worries about (collateral recovered elsewhere not netted against socialized debt) is exactly what `other-coll-usd`/`other-debt-repayable` is netting against.

Since the described precondition (partial liquidation leaves outstanding STX debt while another asset "covered most of the original debt value," yet socialization still fires and cuts `lindex`) cannot occur given this netting check, and there is no externally callable path to invoke `socialize-debt-asset` outside of this gated liquidate flow, the claimed two-principal (A/B) loss scenario is not supported by the code.

I could not fully trace the exact return semantics of `.market-vault`'s `collateral-remove` (whether it returns the amount removed or the remaining balance) due to running out of tool iterations — this detail does not change the conclusion, since the `other-debt-repayable`/`no-collateral-left` netting logic is independent of that return value's exact meaning and already blocks socialization whenever unrecovered collateral value exists elsewhere in the position.

### No vulnerability found for this question.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L879-903)
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
            (unwrap! (contract-call? .v0-market-vault
                                      debt-remove-scaled
                                      borrower
                                      scaled-debt
                                      asset-id) failed-status)
          acc)
        ))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1513-1533)
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
