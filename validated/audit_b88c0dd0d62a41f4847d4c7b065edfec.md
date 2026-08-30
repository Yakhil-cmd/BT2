### Title
Malicious liquidator can round the "leave-dust vs. seize-all" fallback in `liquidate` to permanently withhold a position from bad-debt socialization - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`liquidate` decides whether to force full collateral seizure (and thus enable bad-debt socialization) by checking if the leftover collateral, once converted to a debt amount via `remaining-debt-to-repay`, rounds to exactly `u0`. Because this check is done per-asset and via down-rounding conversions, a liquidator can choose a `debt-amount` that leaves a leftover collateral balance whose derived `remaining-debt-to-repay` computes to a small non-zero value (e.g. `u1`), which is enough to bypass the "seize everything" fallback but too small for anyone else to profitably liquidate. This mirrors the Fraxlend M-32 pattern: a liquidator leaves an uneconomical dust remainder that never gets cleaned up, so the position's bad debt is never socialized and lingers, harming all depositors of the debt asset who did not initiate this liquidation.

### Finding Description
In `liquidate` [1](#0-0) , once the raw amount to seize (`coll-final-raw`) is computed, the code checks whether the residual collateral (`coll-remaining`) is "dust" by converting it into an equivalent debt amount: [2](#0-1) 

If `remaining-debt-to-repay` rounds down to `u0` through the chain of `div-bps-down`/`mul-div-down` conversions, the code forces `coll-final = user-coll-balance` (seize everything, leaving no dust). This is exactly the mitigation the Fraxlend report recommends. However, the liquidator fully controls `debt-amount` (the input parameter), and therefore controls `coll-final-raw` and consequently `coll-remaining`. By choosing `debt-amount` precisely, the liquidator can leave a `coll-remaining` value whose corresponding `remaining-debt-to-repay` rounds to a small non-zero integer (e.g. `1` unit, given `mul-div-up` rounds *up*), which fails the `is-eq remaining-debt-to-repay u0` check and therefore does **not** trigger full seizure. The result is a collateral remainder that is technically "non-zero" from the contract's arithmetic perspective but economically worthless (a handful of wei/sats), so no rational actor will ever liquidate it further.

Downstream, `no-collateral-left` (used to decide whether to call `socialize-debt-asset`) requires `coll-removed` (the vault's *remaining* balance for that asset after removal) to be `u0` [3](#0-2) . Since the liquidator engineered a non-zero leftover, `coll-removed != u0`, so `no-collateral-left` is `false` and `socialize-debt-asset` [4](#0-3)  is never invoked for that debt. The borrower's position is left with dust collateral and (now unsecured) debt that accrues interest indefinitely without ever being written off.

### Impact Explanation
The victims are all other suppliers/lenders of the debt asset's vault (unprivileged principals who did not participate in the liquidation). With the position stuck as unrecoverable bad debt that is never socialized, the vault's accounting overstates recoverable assets: `totalAsset`/outstanding-debt bookkeeping keeps counting this debt as good, meaning share-price/redemption calculations for depositors are inflated relative to real backing. Over time and across multiple such dust positions, this understates real losses until the last depositors to withdraw absorb the shortfall — a protocol insolvency scenario matching the "Critical: protocol insolvency" impact class.

### Likelihood Explanation
Any liquidator can invoke `liquidate` with an arbitrary `debt-amount` and `min-collateral-expected` of `0`; no privileged role or unusual capital is required, only careful selection of the repay amount so the residual converts to a small non-zero value rather than `0`. This can be repeated at will by a griefing/malicious liquidator (or simply happens naturally as a side effect of an attacker preferring to grab the profitable seizure and abandon the unprofitable remainder), making this readily reachable.

### Recommendation
Replace the "rounds exactly to `u0`" heuristic with an explicit minimum economically-meaningful threshold (in USD terms) for `coll-remaining`/`remaining-debt-to-repay`: if the leftover collateral value is below a configured dust threshold (not just literally zero after rounding), force full seizure of `user-coll-balance` and proceed with debt write-off/bad-debt socialization regardless of the exact remainder computed from `debt-amount`.

### Proof of Concept
1. Set up a borrower position that is eligible for full liquidation (LTV ≥ `ltv-liq-full`) with a single collateral asset.
2. As the liquidator, call `liquidate` with a crafted `debt-amount` such that `coll-final-raw` computed in `scale-debt-for-liquidation` leaves a `coll-remaining` whose conversion through `remaining-debt-to-repay` (lines 1477-1485) rounds to a small non-zero integer instead of `u0`.
3. Observe that `coll-final` is set to `coll-final-raw` (not `user-coll-balance`), leaving the borrower with tiny leftover collateral and unpaid debt.
4. Observe `no-collateral-left` evaluates to `false` (since `coll-removed != u0`), so `socialize-debt-asset` is never called and the position's remaining debt is never written off.
5. Repeat over time; interest accrues on the unbacked debt while no further liquidation occurs due to the dust amount being uneconomical to liquidate, growing the shortfall that other depositors must eventually bear.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1470-1486)
```text
    ;; debt scaling for storage
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1526-1532)
```text
          (no-collateral-left (and
                                (is-eq coll-removed u0)
                                (or
                                  (is-eq (len (get collateral pos-full)) u1)
                                  (and
                                    (is-eq (len (get collateral pos-full)) (len (get collateral position)))
                                    (is-eq other-debt-repayable u0))))))
```
