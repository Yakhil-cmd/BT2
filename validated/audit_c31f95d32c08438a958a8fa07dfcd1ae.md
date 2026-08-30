## Finding [1](#0-0) 

### Title
Bad-debt socialization can trigger while borrower still holds unliquidated collateral due to `div-bps-down` rounding `other-debt-repayable` to zero — ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`liquidate()` decides whether to socialize a borrower's remaining debt onto all vault suppliers based on whether the borrower's *other* (non-target) collateral could still repay outstanding debt. That check, `other-debt-repayable`, is computed with `div-bps-down`, which — exactly like the `TotalVotingPower`/`bps2Uint()` rounding issue in the referenced report — rounds down to `0` whenever the input USD value is small relative to the divisor `(+ BPS liq-penalty-max)`. When this happens, code treats a position that still has real, positive-value collateral as having **no collateral left**, and prematurely socializes the borrower's remaining debt to all lenders while the borrower's dust collateral stays with them, unliquidated and unrecovered.

### Finding Description
In `liquidate()`, after seizing the target collateral asset, the contract estimates how much of the borrower's *other* collateral (in different assets) could still cover outstanding debt: [2](#0-1) 

- `other-coll-usd` = value of the borrower's remaining (non-target) collateral.
- `other-debt-repayable` = `div-bps-down(other-adj, ...)` chained through `mul-div-down`/`mul-div-up`, ultimately computing how much debt that collateral could theoretically repay.
- `no-collateral-left` is `true` when `coll-removed == 0` **and** (`other-debt-repayable == 0`), which is the gate used to decide whether the borrower's remaining debt is stripped from the position and socialized to all suppliers via `socialize-debt-asset`.

`div-bps-down` is defined as: [3](#0-2) 

`(/ (* x BPS) y)` — integer division that truncates. When `other-coll-usd` is small enough that `other-coll-usd * BPS < (BPS + liq-penalty-max)`, the intermediate `other-adj` (and therefore the final `other-debt-repayable`) rounds down to `0`, exactly as `bps2Uint()` rounds `proposalThreshold()`/`quorumVotes()` to `0` in the referenced Sherlock finding when `TotalVotingPower` is low.

This is not a deliberate safety design decision — it is an unintended consequence of integer truncation in a threshold check that gates an irreversible, protocol-wide action (bad-debt socialization).

### Impact Explanation
When `other-debt-repayable` incorrectly rounds to `0` while the borrower still holds collateral of small-but-nonzero USD value in another asset:
- The borrower's remaining debt is stripped from their position and distributed across all suppliers of that debt asset via `socialize-debt-asset`, i.e., every lender's claim is diluted to cover a loss that a subsequent liquidation of the borrower's remaining collateral could have partially or fully avoided.
- The borrower's small remaining collateral is left in their position, effectively unreachable/unliquidated once their debt for that asset has already been zeroed by socialization — the value is not returned to suppliers and is not seized by a liquidator.
- Because bad debt is written off directly against supplier funds (a shared pool), this is a case of "socialization charged to all suppliers" being triggered earlier/more broadly than the protocol's own accounting says is warranted, permanently reducing the recoverable value backing supplier deposits.

This lands in the **temporary/permanent freezing of funds** (and potentially contributes to protocol insolvency) impact class, since supplier funds are socialized away based on an incorrect zero-value threshold rather than the true value of the borrower's remaining collateral.

### Likelihood Explanation
This requires a borrower position where, after a partial/targeted liquidation empties the specific target collateral asset (`coll-removed == 0` on a subsequent call, or the position naturally has that asset already at zero), the borrower's *other* collateral asset value is low enough in USD terms that `other-adj`'s numerator (`other-coll-usd * BPS`) is smaller than `BPS + liq-penalty-max` (a low double-digit-thousands divisor). This is realistic for dust collateral balances, low-priced/low-decimal collateral assets, or late-stage liquidations where most collateral has already been drained — a scenario multi-collateral liquidations and `liquidate-multi` batch calls make routinely reachable by ordinary, unprivileged liquidators.

### Recommendation
Do not use a rounded-to-zero `other-debt-repayable` as a proxy for "no collateral value remains." Instead, gate `no-collateral-left` on the underlying USD value (`other-coll-usd == 0`) directly, or round `div-bps-down`/`other-adj` up when used in a threshold check that decides whether to skip liquidation and go straight to socialization, so that any nonzero remaining collateral value is not treated as zero.

### Proof of Concept
1. Borrower has two collateral assets: Asset A (target, e.g., sBTC) worth most of the position, and Asset B (other) with a small remaining USD value (e.g., a handful of cents after prior partial liquidations/withdrawals) plus outstanding debt.
2. Liquidator calls `liquidate()` targeting Asset A on a call where Asset A's seizable amount is already `0` (e.g., a second liquidation call after A was fully seized in a prior liquidation, or a batch entry via `liquidate-multi`), so `coll-removed == 0`.
3. `other-coll-usd` (Asset B's value) is computed as `total-collateral-usd - target-coll-full-usd`, a small positive number.
4. `other-debt-repayable` is computed via `div-bps-down(other-adj, ...)`; because `other-coll-usd` is small, the chain of `mul-div-down`/`div-bps-down` truncates to `0`.
5. `no-collateral-left` evaluates `true` even though Asset B still holds positive value, and the borrower's remaining debt is stripped and run through `socialize-debt-asset`, distributing the loss across all suppliers of that debt asset — while Asset B's dust value remains unliquidated in the borrower's position.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L171-176)
```text
(define-private (mul-bps-down (x uint) (y uint))
  (/ (* x y) BPS))

(define-private (div-bps-down (x uint) (y uint))
  (/ (* x BPS) y))

```

**File:** mainnet/contracts/market/v0-4-market.clar (L1514-1532)
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
