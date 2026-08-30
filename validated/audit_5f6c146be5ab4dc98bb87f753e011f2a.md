### Title
Rounding of the "remaining collateral" dust check to zero causes uncompensated collateral seizure during liquidation - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
In `liquidate`, when a borrower's collateral balance exceeds the amount required to cover the capped, liquidated debt (`coll-final-raw`), the function computes `remaining-debt-to-repay` for the leftover ("dust") collateral. If this computed value rounds down to `0` (an integer-division artifact caused by USD→token conversion through `mul-div-down`), the code does **not** just skip the dust — it forces `coll-final` to become the entire `user-coll-balance`, i.e. it seizes the whole remaining collateral for the liquidator without charging any additional debt repayment for it.

### Finding Description
The relevant logic: [1](#0-0) 

```
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

`coll-final-raw` and `debt-to-repay` are already correctly computed as the amount of collateral that corresponds to the debt actually being repaid, via `calc-final-liquidation-amounts` and `scale-debt-for-liquidation`. [2](#0-1) 

The additional `remaining-debt-to-repay` branch is meant to detect whether the leftover collateral (`coll-remaining`) is worth anything in debt terms. `rem-debt-tokens` is derived from `mul-div-down(rem-debt-usd, 10^debt-decimals, debt-price)` — a plain integer division. When `debt-decimals` is low (e.g. 6-8, as with USDC/USDT/WBTC-style tokens) relative to the USD-normalized precision used for `rem-coll-usd`/`rem-debt-usd`, or when the leftover collateral value is simply small relative to `debt-price`, this division rounds down to `0`. Because `rem-scaled`/`remaining-debt-to-repay` are then also `0`, the branch that should mean "no meaningful debt is left to repay for the leftover, and it can be considered negligible dust" instead triggers `coll-final := user-coll-balance` — handing the **entire** remaining collateral to the liquidation flow (which routes it to `actual-receiver`, i.e., the liquidator) while `debt-to-repay` charged to the vault (used in `vault-system-repay` and `debt-remove-scaled`) is only the amount computed from `debt-final`/`scaled-to-remove`, **not** inflated to account for the extra collateral now being seized. [3](#0-2) 

This is the same fundamental root cause as the referenced report: an integer division (`volume/price` there, `rem-debt-usd * 10^decimals / debt-price` here) that is expected to represent a proportional, non-zero amount rounds down to zero because of decimals/price magnitude mismatches, and the surrounding logic treats that zero as "nothing owed" rather than guarding against it — except here the zero silently expands the amount seized from an unprivileged third party (the borrower) rather than simply zeroing out the caller's own entitlement.

### Impact Explanation
The borrower (an unprivileged party who did not initiate the transaction) loses collateral beyond what is proportional to the debt actually repaid on their behalf, and the liquidator (the caller) receives that "free" excess collateral. This is direct theft of a user's collateral (funds at rest) via a seizure that exceeds its intended bound, which the same borrower would not have suffered had `remaining-debt-to-repay` correctly reflected a small-but-nonzero remaining obligation (or had the dust simply been left unliquidated instead of being swept away for free).

### Likelihood Explanation
This requires no attacker capital or special privilege beyond calling `liquidate` on an eligible position (LTV above `LTV-LIQ-PARTIAL`) where the borrower's collateral balance for the liquidated asset leaves a "remaining" (`coll-remaining > 0`) portion whose USD value, once converted through `mul-div-down(rem-debt-usd, 10^debt-decimals, debt-price)`, rounds to zero. This is realistic for low-decimals debt assets or when the leftover collateral value is a small fraction of one debt-token unit — a fairly ordinary condition during partial liquidations, not an edge case requiring adversarial setup.

### Recommendation
Do not use "`remaining-debt-to-repay == 0`" as the trigger to sweep the entire `user-coll-balance` for free. Instead, either (a) only sweep the leftover collateral if its value is below an explicit, protocol-defined dust threshold (independent of the debt-token's decimals/price rounding), or (b) require `remaining-debt-to-repay` (or an equivalent minimum debt unit) to be added to `debt-to-repay`/`scaled-to-remove` whenever the extra collateral is swept, so that the liquidator always pays proportionally for whatever collateral they receive.

### Proof of Concept
1. Configure an egroup/asset pair where the debt asset has low decimals (e.g., 6) and a collateral asset with a high USD price per base unit, so that `debt-price` is large relative to `10^debt-decimals` for small `rem-debt-usd` amounts.
2. Set up a borrower position that crosses into the partial-liquidation LTV zone such that after `calc-final-liquidation-amounts`/`scale-debt-for-liquidation`, `coll-final-raw < user-coll-balance`, leaving `coll-remaining > 0`.
3. Ensure `coll-remaining`'s USD value, after `div-bps-down` and conversion via `mul-div-down(rem-debt-usd, 10^debt-decimals, debt-price)`, is small enough to floor to `0` (e.g., a leftover collateral value worth less than one debt-token base unit at the given price).
4. Call `liquidate` as any third-party liquidator with a `debt-amount` that produces this scenario.
5. Observe that `coll-final` is set to the full `user-coll-balance` (via the `is-eq remaining-debt-to-repay u0` branch) and is transferred to the liquidator via `collateral-remove`, while `debt-to-repay`/`vault-system-repay` only reflects the smaller, originally-computed debt amount — the borrower loses collateral (`coll-remaining`) for which no additional debt was repaid.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L856-877)
```text
;; Converts to scaled units, caps at current debt, calculates final collateral
;; Returns: { scaled-to-remove: uint, debt-to-repay: uint, coll-final: uint }
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1493-1512)
```text
    (asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)

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
