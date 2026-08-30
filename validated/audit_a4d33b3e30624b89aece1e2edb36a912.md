### Title
Liquidation dust-sweep seizes a borrower's entire remaining collateral for free when the marginal repayable debt rounds to zero - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`liquidate` computes the collateral a liquidator is owed (`coll-final-raw`) from the debt it repays, then checks whether the *leftover* (un-seized) collateral (`coll-remaining`) could still be used to repay any additional debt. If that marginal debt amount rounds down to `u0` (dust), the code does not leave the dust with the borrower — instead it sets `coll-final` to the borrower's **entire** collateral balance, letting the liquidator take all of it while `debt-to-repay` (what the liquidator must pay) is left unchanged. This mirrors the M-6 report's "leftover amount from a rounding-affected computation is never returned to its rightful owner" bug class, except here the leftover is handed to a third party (the liquidator) rather than merely stranded.

### Finding Description
In the liquidation flow:
```
(coll-remaining (- user-coll-balance coll-final-raw))
(remaining-debt-to-repay
  (if (> coll-remaining u0)
    (let (...)
      (mul-div-up rem-scaled rem-borrow-index INDEX-PRECISION))
    u1))
(coll-final (if (is-eq remaining-debt-to-repay u0) user-coll-balance coll-final-raw)))
``` [1](#0-0) 

`coll-final-raw` is computed from `debt-final`/`scale-debt-for-liquidation`, which is the collateral mathematically owed for the debt actually being repaid (`debt-to-repay`), computed a few lines earlier: [2](#0-1) 

`debt-to-repay` is fixed before this dust-check and is **not** increased when `coll-final` is bumped up to `user-coll-balance`: [3](#0-2) 

The liquidation then executes with the swept `coll-final` value, removing it from the borrower's collateral and sending it to the liquidator (or a receiver of the liquidator's choosing) without any corresponding increase in the debt repaid: [4](#0-3) 

The same pattern exists in `local-testing/contracts/market/market.clar` at the analogous lines. [5](#0-4) 

Because `user-coll-balance` still belongs to the borrower (they retain the right to withdraw it via `collateral-remove` once healthy), this "dust" is not actually stuck or unusable to anyone before the liquidation call — it is a normal, spendable/withdrawable balance owned by the borrower. The dust-sweep logic unilaterally reassigns it to the liquidator as an unpaid bonus whenever the marginal repayable-debt-from-dust calculation rounds to zero, which can be triggered by a liquidator choosing a `debt-amount` that leaves a small `coll-remaining`.

### Impact Explanation
This is a value transfer from an unprivileged borrower (victim) to an unprivileged liquidator (attacker) via the shared state of the borrower's collateral position in `market-vault`. The liquidator receives collateral strictly in excess of what the repaid debt entitles them to, with no compensating debt repayment — theft of collateral funds at rest belonging to the borrower. This lands in the **Critical** impact bucket (direct theft of user funds at rest).

### Likelihood Explanation
Any address can call `liquidate` once a position crosses the partial-liquidation LTV threshold; a liquidator can select `debt-amount` such that `coll-remaining` is small enough that `remaining-debt-to-repay` rounds to `0` (this is a rounding/dust condition that is trivially reachable given attacker control over the `debt-amount` parameter), making the extra "free" collateral sweep repeatable and attacker-controllable.

### Recommendation
When `remaining-debt-to-repay` rounds to zero, leave `coll-final` as `coll-final-raw` (do not sweep the borrower's remaining collateral to the liquidator). If dust collateral needs eventual cleanup, it should remain claimable by the borrower (who can withdraw it normally once healthy) rather than being unilaterally reassigned to the liquidator without payment.

### Proof of Concept
1. Borrower has a partially-liquidatable position with collateral balance `user-coll-balance` in asset A and debt in asset B.
2. Liquidator calls `liquidate` with a `debt-amount` chosen (via off-chain simulation) such that after computing `coll-final-raw`, the leftover `coll-remaining = user-coll-balance - coll-final-raw` is small enough that `rem-debt-tokens`/`rem-scaled` round down to a value whose `mul-div-up` result (`remaining-debt-to-repay`) equals `u0`.
3. `coll-final` is then set to `user-coll-balance` instead of `coll-final-raw`, while `debt-to-repay` (computed earlier from `debt-final`) is unchanged.
4. `collateral-remove` transfers the entire `user-coll-balance` to the liquidator/receiver, but the liquidator only repaid `debt-to-repay`, which corresponds to `coll-final-raw`, not `user-coll-balance`.
5. Borrower is left with `u0` collateral instead of `coll-remaining`, having received no debt reduction credit for that difference — a direct, uncompensated loss.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1470-1475)
```text
    ;; debt scaling for storage
    (curr-scaled (get-account-scaled-debt borrower debt-aid))
    (scaled-info (scale-debt-for-liquidation debt-final coll-actual curr-scaled debt-aid))
    (scaled-to-remove (get scaled-to-remove scaled-info))
    (debt-to-repay (get debt-to-repay scaled-info))
    (coll-final-raw (get coll-final scaled-info))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1495-1496)
```text
    ;; execute liquidation
    (try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1498-1512)
```text
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

**File:** local-testing/contracts/market/market.clar (L1499-1509)
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
