### Title
Liquidation "dust" logic seizes a borrower's entire remaining collateral for free when the leftover value rounds down to zero debt tokens - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
In `liquidate`, when the collateral actually needed to cover `debt-final` (`coll-final-raw`) is less than the borrower's total balance of that collateral asset (`user-coll-balance`), the contract computes whether the leftover (`coll-remaining`) is worth liquidating further. If the conversion of that leftover to debt tokens (`remaining-debt-to-repay`) rounds down to `u0`, the code seizes the borrower's **entire** collateral balance (`user-coll-balance`) instead of only `coll-final-raw`, while the liquidator only repays `debt-to-repay` (based on `coll-final-raw`). This mirrors the `_collectRentAction` bug class: a branch chosen by comparing two derived quantities silently changes which value (partial vs. full) is used for a state-changing payout, and one branch systematically over-allocates value to one unprivileged party (the liquidator) at the expense of another (the borrower).

### Finding Description
The relevant code:
```clarity
;; mainnet/contracts/market/v0-4-market.clar:1470-1509
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
``` [1](#0-0) 

`coll-final` decides how much collateral is actually removed from the borrower and sent to the liquidator:
```clarity
(coll-removed (try! (contract-call? .v0-market-vault
                    collateral-remove
                    borrower
                    coll-final
                    collateral-ft
                    coll-aid
                    actual-receiver)))
``` [2](#0-1) 

However, only `debt-to-repay` (computed from `coll-final-raw`, not `user-coll-balance`) is actually repaid to the vault:
```clarity
(try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))
``` [3](#0-2) 

The `u1` sentinel used when `coll-remaining` is `0` is itself suspicious - it guarantees `remaining-debt-to-repay` is never `u0` in the "no remainder" case, which forces `coll-final = coll-final-raw` there; but whenever there *is* a nonzero leftover whose USD value converts to `0` debt tokens due to rounding (`mul-div-down`), the borrower's **whole** remaining collateral for that asset is swept to the liquidator without any additional debt being repaid for it. The rounding-to-zero condition depends only on `coll-remaining`, `coll-price`, `debt-price`, and `debt-decimals` - none of which the liquidator needs special privilege to trigger; a liquidator can choose `debt-amount` to intentionally leave a small `coll-remaining` whose converted debt value rounds to zero, then receive the full balance instead of the mathematically-justified `coll-final-raw`.

### Impact Explanation
This is a "seizure exceeding its bound" scenario: the liquidator (an unprivileged caller) extracts more of the borrower's (an unprivileged victim's) collateral than the debt-repayment and liquidation-penalty math justifies. Because only `debt-to-repay` is transferred to the vault while the borrower loses `user-coll-balance` (not `coll-final-raw`), the borrower suffers a permanent, uncompensated loss of collateral value equal to `coll-remaining` beyond what the liquidation-penalty formula allows. This is a direct theft of a borrower's funds at rest, landing on the **Critical** impact tier (direct theft of user funds at rest other than unclaimed yield).

### Likelihood Explanation
The liquidator fully controls `debt-amount` (the input to `process-debt-asset`), and thus can tune `debt-actual-usd`/`coll-expected` so that `coll-remaining` is a small but nonzero amount whose USD value, after applying `liq-penalty-max` and converting via `debt-decimals`/`debt-price`, rounds to `0` in `mul-div-down`. This is achievable for any position that is partially liquidatable (LTV between `ltv-liq-partial` and `ltv-liq-full`, where the liquidation factor caps `max-debt-usd` below the full debt) and where the collateral asset has a comparatively large decimal count paired with a debt asset priced/denominated such that small residual USD amounts truncate to zero tokens. Because the liquidator picks the exact `debt-amount`, the likelihood of successfully engineering this rounding condition is high whenever a partial liquidation applies.

### Recommendation
Do not conflate "dust cleanup" (giving away negligible leftover collateral) with an unconditional full-balance sweep. Either:
1. Bound the giveaway explicitly to a hard-coded small dust threshold (e.g., a few wei) rather than deriving it from a rounding-to-zero condition on unrelated decimal/price combinations, or
2. When `remaining-debt-to-repay` rounds to `0`, also cap `coll-final` extraction value by the actual USD value repaid, and if the leftover would still amount to something you intend to sweep as dust, transfer only up to the true bound `coll-final-raw + a fixed max dust amount`, not `user-coll-balance` unconditionally.
Also add an invariant test asserting `coll-final <= mul-div-up(debt-to-repay-derived-usd, BPS + liq-penalty-max, BPS)` converted to collateral units, i.e., that seized collateral never exceeds the penalty-adjusted value of debt actually repaid by more than a small dust bound.

### Proof of Concept
1. Alice deposits collateral asset C (e.g. an asset with 18 decimals) and borrows debt asset D (e.g. 6-decimal stablecoin) until her position crosses `ltv-liq-partial`, entering graduated (partial) liquidation.
2. Attacker (liquidator) computes `max-debt-usd` from `calc-liquidation-params` for Alice's current LTV, then chooses `debt-amount` such that `coll-actual`/`coll-final-raw` (from `scale-debt-for-liquidation`) leaves a `coll-remaining` whose USD value after `div-bps-down(rem-coll-usd, BPS+liq-penalty-max)` and `mul-div-down(rem-debt-usd, 10^debt-decimals, debt-price)` truncates to `0` debt tokens (feasible by iterating `debt-amount` off-chain to hit the rounding boundary).
3. Attacker calls `liquidate(alice, C, D, debt-amount, 0, none, none)`.
4. `remaining-debt-to-repay` evaluates to `u0`, so `coll-final` is set to `user-coll-balance` (Alice's full collateral C balance), while `vault-system-repay` only repays `debt-to-repay` (derived from `coll-final-raw`, smaller than `user-coll-balance`'s implied value).
5. Alice loses her entire collateral balance in asset C, while only a fraction of the corresponding debt was actually repaid - the difference is pure loss to Alice and pure gain to the liquidator beyond the penalty-adjusted bound.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1470-1512)
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

    (asserts! (not (is-liquidation-paused debt-aid)) ERR-LIQUIDATION-PAUSED)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    (asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
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
