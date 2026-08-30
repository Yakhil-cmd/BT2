## Title
Liquidator's batch liquidation (`liquidate-multi`) can be DoS'd via an `unwrap-panic` runtime abort when a debt asset lacks a cached borrow index - ([File: mainnet/contracts/market/v0-4-market.clar])

## Summary
`liquidate-multi` bundles several independent borrowers into one atomic call via `(map call-liquidate positions)` [1](#0-0) . Each individual `liquidate` call unconditionally calls `scale-debt-for-liquidation`, which does `(unwrap-panic (get-cached-indexes asset-id))` [2](#0-1) . The cache is only primed for assets present in the borrower's *current* debt list at the top of `liquidate`, via `accrue-user-debts (get debt pos-full)` [3](#0-2) . If a borrower has zero remaining scaled debt for the targeted `debt-ft` (e.g. because they just repaid it in full, which deletes the map entry via `remove-user-scaled-debt`) [4](#0-3) , that asset never gets accrued/cached, `get-cached-indexes` returns `none`, and `unwrap-panic` triggers an unrecoverable Clarity runtime abort. Because Clarity's `map` does not catch runtime panics the way it isolates `(response ok/err)` values, this single panicking element aborts the *entire* `liquidate-multi` transaction — reverting every other, otherwise-successful liquidation bundled in the same call.

## Finding Description
`scale-debt-for-liquidation` is called unconditionally inside `liquidate` regardless of whether the borrower actually still owes the targeted debt asset:
```
(curr-scaled (get-account-scaled-debt borrower debt-aid))
(scaled-info (scale-debt-for-liquidation debt-final coll-actual curr-scaled debt-aid))
``` [5](#0-4) 

`get-account-scaled-debt` degrades gracefully to `u0` when the debt map entry is absent (via `debt-scaled`'s `default-to u0`) [6](#0-5) , so `curr-scaled` alone doesn't panic. However `scale-debt-for-liquidation` still unconditionally does:
```
(borrow-index (get index (unwrap-panic (get-cached-indexes asset-id))))
``` [7](#0-6) 

`get-cached-indexes` is a plain `map-get?` against `index-cache`, keyed on `{ timestamp: stacks-block-time, aid }` [8](#0-7) , and that cache is populated by `accrue-and-cache`, which is only invoked (within `liquidate`) for assets present in `(get debt pos-full)` at the moment the position is fetched [3](#0-2) . If the borrower has just fully repaid `debt-aid` (removing it from the obligation's debt list), no `accrue-and-cache` call for `debt-aid` ever happens for that borrower during `liquidate`, so `get-cached-indexes debt-aid` is `none` and `unwrap-panic` aborts the transaction with a runtime error — not a recoverable `(err ...)`.

Because `liquidate-multi` composes independent borrower liquidations with `(map call-liquidate positions)` [1](#0-0) , and Clarity aborts the whole transaction on an unrecovered runtime panic anywhere in its execution, a single stale/incorrect entry for one borrower nukes every other borrower's liquidation bundled in that call — even ones that were perfectly valid and would otherwise have succeeded.

The victim/attacker relationship: a borrower (Borrower A) who is about to be liquidated for `debt-ft`=X can front-run/race a liquidator's `liquidate-multi` transaction by repaying their entire X debt in the same or an earlier block. When the liquidator's batch executes, the position entry for Borrower A triggers the panic and the whole batch — including the liquidation of an unrelated, unhealthy Borrower B bundled in the same call — reverts. This delays Borrower B's liquidation (temporary freezing of the collateral/seizure that should have executed), and — combined with market moves during the delay — increases the risk of uncollateralized bad debt being socialized onto suppliers, i.e. protocol insolvency risk from delayed liquidation. This is not merely the caller-liquidator harming themselves; Borrower B (an unrelated third party in the same batch) is the one who fails to be liquidated on time due to Borrower A's action.

## Impact Explanation
This falls under "temporary freezing of funds" (liquidation of an unhealthy position that should execute is blocked/delayed by an unrelated third party's action), with a secondary risk of contributing to protocol insolvency if the delay allows further price decline before the position can be liquidated in a subsequent, isolated call.

## Likelihood Explanation
This requires a liquidator to opportunistically batch multiple unrelated borrowers' liquidations in one `liquidate-multi` call (a documented, encouraged usage pattern - the code comments describe it as preventing "front-running attacks that prevent bad debt socialization"), and a borrower in that batch to repay their targeted debt asset in the same or a prior block. Both actions are unprivileged and require no special access; a borrower being liquidated has direct incentive to attempt exactly this kind of repayment race, and any legitimate `liquidate-multi` caller can inadvertently include such an entry.

## Recommendation
In `scale-debt-for-liquidation` (and similarly `remaining-debt-to-repay`'s use of `(unwrap-panic (get-cached-indexes debt-aid))`), replace `unwrap-panic` with a graceful fallback (e.g., `default-to` a freshly computed/accrued index, or an explicit `unwrap!`/`asserts!` returning an `err`) so a missing cache entry produces a recoverable error for that single position instead of an unconditional runtime panic. This ensures `liquidate-multi`'s `map` can isolate per-position failures as intended, rather than letting one malformed/edge-case entry abort the entire batch.

## Proof of Concept
1. Borrower A opens a position with collateral and debt in asset X (debt-ft), becoming eligible for partial liquidation.
2. A liquidator prepares `liquidate-multi` with two entries: Borrower A (debt-ft = X) and Borrower B (an unrelated, genuinely unhealthy position, debt-ft = Y).
3. Borrower A submits (or has already submitted, landing in an earlier block or the same block ahead in ordering) a `repay` transaction that fully repays their debt in X, deleting the `debt` map entry for `{id: A, asset: X}` via `remove-user-scaled-debt` [4](#0-3) .
4. The liquidator's `liquidate-multi` executes: for the Borrower A entry, `liquidate` runs `accrue-user-debts` over Borrower A's now-empty-of-X debt list (so X is never accrued/cached), then reaches `scale-debt-for-liquidation`, which calls `(unwrap-panic (get-cached-indexes X))` and panics.
5. The Clarity VM aborts the entire `liquidate-multi` transaction, reverting Borrower B's liquidation along with Borrower A's failed one, even though Borrower B's liquidation was independently valid.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L858-877)
```text
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

**File:** mainnet/contracts/market/v0-4-market.clar (L966-967)
```text
        data: {
          was-paused: was-paused,
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1405-1407)
```text
    ;; accrue FIRST - populates cache for zToken price resolution
    (u-debt (accrue-user-debts (get debt pos-full)))
    (u-coll (accrue-user-collateral (get collateral pos-full)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1471-1472)
```text
    (curr-scaled (get-account-scaled-debt borrower debt-aid))
    (scaled-info (scale-debt-for-liquidation debt-final coll-actual curr-scaled debt-aid))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1593-1599)
```text
(define-public (liquidate-multi
                (positions (list 64 { borrower: principal,
                                      collateral-ft: <ft-trait>,
                                      debt-ft: <ft-trait>,
                                      debt-amount: uint,
                                      min-collateral-expected: uint })))
  (ok (map call-liquidate positions)))
```

**File:** local-testing/contracts/market/market-vault.clar (L244-252)
```text
(define-private (remove-user-scaled-debt (user-id uint) (asset-id uint) (amount uint))
  (let ((key { id: user-id, asset: asset-id })
        (current-scaled-debt (default-to u0 (get scaled (map-get? debt key)))) ;; graceful default to u0
        (legal? (asserts! (<= amount current-scaled-debt) ERR-INSUFFICIENT-DEBT))
        (updated-scaled-debt (- current-scaled-debt amount)))
    (if (is-eq updated-scaled-debt u0)
        (map-delete debt key)
        (map-set debt key { scaled: updated-scaled-debt }))
    (ok updated-scaled-debt)))
```

**File:** mainnet/contracts/market/v0-market-vault.clar (L311-315)
```text
(define-read-only (get-debt (id uint) (asset uint))
  (unwrap-panic (map-get? debt { id: id, asset: asset })))

(define-read-only (debt-scaled (id uint) (asset uint))
  (default-to u0 (get scaled (map-get? debt { id: id, asset: asset }))))
```
