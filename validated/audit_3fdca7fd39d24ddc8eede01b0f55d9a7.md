### Title
Silent failure of bad-debt socialization inside `liquidate-multi` leaves seized collateral gone but debt unwritten-off, harming vault depositors - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`liquidate-multi` batches liquidations via `(map call-liquidate positions)`. Unlike `try!`/`unwrap!`/`asserts!`, Clarity's `map` does **not** propagate a nested call's `(err ...)` up to abort the enclosing transaction — it simply collects the response (ok or err) into a list. Inside a single `liquidate` call, collateral seizure (`collateral-remove`, which transfers tokens to the liquidator) and the debt repay/removal for the primary asset happen via `contract-call?` to `.v0-market-vault`/vaults and commit as soon as those calls return `(ok ...)`. Only *afterwards* does `liquidate` attempt "bad debt socialization" via `fold socialize-debt-asset ...` and gate it with `(asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)`. If that assert fails, `liquidate` (called directly, not through `contract-call?`, so no rollback boundary is created for it) returns `(err ...)` — but because `call-liquidate`/`liquidate-multi` swallow this via `map` and the outer transaction still returns `(ok (list ...))`, all the already-committed sub-calls (collateral transferred to the liquidator, `debt-remove-scaled` on the liquidated asset) remain committed while the bad-debt write-off for the borrower's *other* debt assets is skipped.

### Finding Description
In `liquidate` (mainnet/contracts/market/v0-4-market.clar), the sequence is:

1. `(try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))` — liquidator's funds repay the vault. [1](#0-0) 

2. `debt-remove-scaled` and `collateral-remove` are called via `contract-call?` and their results committed once they return `(ok ...)`. `collateral-remove` itself transfers the seized collateral out to the liquidator (`send-tokens`) before returning. [2](#0-1) [3](#0-2) 

3. If `no-collateral-left` is true, the position's remaining debt list is folded over `socialize-debt-asset`, which calls `vault-socialize-debt`, refreshes the index cache, and calls `debt-remove-scaled` — each guarded with `unwrap!` that yields `{ success: false }` on any failure instead of aborting: [4](#0-3) 

4. The overall socialization result is only checked with `(asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)`, which fails `liquidate` (returns err) if any nested step failed. [5](#0-4) 

5. `liquidate-multi` invokes `liquidate` indirectly through `call-liquidate`, using `map` — not `try!` — over the list of positions, so an `(err ...)` from any individual `liquidate` call is captured as a list element rather than aborting the whole `liquidate-multi` transaction: [6](#0-5) [7](#0-6) 

Because `call-liquidate` invokes `liquidate` as a direct in-contract function call (not `contract-call?`), no Clarity rollback boundary wraps that specific invocation; the only rollback boundaries created and committed are those of the nested `contract-call?`s that already succeeded (`vault-system-repay`, `debt-remove-scaled`, `collateral-remove`). When the batch call ultimately returns `(ok (list ...))` (because at least one position map-element is `ok`, or simply because `map` never aborts regardless of individual `err`s), the whole top-level transaction commits. This leaves the borrower with zero collateral (already seized and sent to the liquidator) but debt that was *supposed* to be socialized (written off against the vault's LPs) still on the books, because that specific write-off step failed and its own state changes were never applied.

### Impact Explanation
The vault (its depositors/LPs) is the victim: its accounting for `total-debt`/`principal-scaled` continues to reflect debt from a position that has zero collateral backing and can never repay. This debt keeps accruing "interest" that is never actually collectible, permanently distorting utilization/APY calculations and effectively freezing/misallocating value that legitimate depositors are owed, without any attacker action against them directly — the harm arises purely from the state left behind by the swallowed failure inside a batched liquidation. This is a **temporary/permanent freezing of funds** for the vault's LPs (their claim is diluted by unrecoverable, un-written-off debt), distinct from the caller's (liquidator's) own risk, since the liquidator already received the seized collateral regardless of the socialization outcome.

### Likelihood Explanation
The failure mode requires `vault-socialize-debt`, the mid-fold `map-set index-cache`/`vault-accrue` call, or `debt-remove-scaled` for a *secondary* debt asset to return an error while the *primary* debt-repay/collateral-remove for the position already succeeded. This can plausibly happen when the borrower holds debt in multiple assets and one of those secondary asset vaults is paused, at a cap, or in some other guarded state that causes its `debt-remove-scaled`/`vault-socialize-debt` call to fail — none of which requires DAO compromise, just an ordinary permissionless multi-asset borrower position and calling `liquidate-multi` (or even a single `liquidate` embedded inside another wrapper that swallows its error) at the right moment. The bug is purely a consequence of `map` not propagating nested-call failure the way `try!` does, combined with `liquidate` not being called through `contract-call?`.

### Recommendation
- In `liquidate`, ensure that if bad-debt socialization fails, the entire liquidation (including collateral seizure and primary debt removal) is rolled back atomically. This can be achieved by invoking `liquidate` from `call-liquidate` through an explicit self `contract-call?` (crossing the rollback boundary) so a returned `err` truly discards all of that liquidation's state changes, or by restructuring `liquidate-multi`/`call-liquidate` to use `try!` per position and only continue the batch when the individual result can be safely discarded.
- Alternatively, make socialization failure impossible to silently skip: validate that all target vaults for the borrower's remaining debt are eligible for socialization *before* seizing any collateral (fail-fast, symmetric with the existing "FAIL-FAST" health check pattern already used earlier in `liquidate`).
- Add tests specifically for `liquidate-multi` where one position's socialization step fails (e.g., a secondary debt vault paused) to confirm collateral is not released without the corresponding debt being written off.

### Proof of Concept
1. Set up a borrower with collateral in asset A and debt in two assets: `debt-aid` (asset B, to be liquidated) and asset C (secondary debt).
2. Pause (or otherwise make failing) the `debt-remove-scaled`/`vault-socialize-debt` path for asset C's vault (e.g., via its own pause-states toggled for `debt-remove`/`socialize`, a permissionless/no-DAO-required precondition already present in the vault's pause design, or simply hitting a cap/insufficient-debt edge case).
3. Liquidator calls `liquidate-multi` with a single position entry targeting this borrower for asset B, sized so that `coll-removed` results in `no-collateral-left = true`.
4. Trace execution: `vault-system-repay`, `debt-remove-scaled` (asset B), and `collateral-remove` (asset A, transferring tokens to the liquidator) all succeed and commit via their own `contract-call?` boundaries.
5. `fold socialize-debt-asset` then processes asset C's entry, hits the induced failure, returns `{ success: false }`; `(asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)` makes `liquidate` return `(err ERR-BAD-DEBT-SOCIALIZATION-FAILED)`.
6. Because `call-liquidate`/`liquidate-multi` use `map` (not `try!`), `liquidate-multi` returns `(ok (list (err ERR-BAD-DEBT-SOCIALIZATION-FAILED)))` — the transaction succeeds overall.
7. Post-transaction: query the borrower's position — collateral for asset A is now zero (liquidator received it), but the borrower's debt for asset C remains fully intact and continues accruing interest in the vault, with no offsetting write-off ever applied — a permanent, uncollectible liability now silently borne by that vault's other depositors.

*(Note: full confirmation of the exact Clarity rollback semantics for non-`contract-call?` nested public-function invocations, and the precise conditions under which `vault-socialize-debt`/`debt-remove-scaled` can fail for a secondary asset without DAO involvement, could not be independently executed/tested within this review — a live Devin session with test-suite execution would be needed to concretely reproduce and confirm the exact failure trigger and resulting on-chain state.)*

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

**File:** mainnet/contracts/market/v0-4-market.clar (L907-918)
```text
(define-private (call-liquidate (position { borrower: principal,
                                            collateral-ft: <ft-trait>,
                                            debt-ft: <ft-trait>,
                                            debt-amount: uint,
                                            min-collateral-expected: uint }))
  (liquidate (get borrower position)
             (get collateral-ft position)
             (get debt-ft position)
             (get debt-amount position)
             (get min-collateral-expected position)
             none   ;; collateral-receiver defaults to liquidator
             none)) ;; price-feeds not supported in batch - update prices separately
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1544-1548)
```text
                    (if (> (len fresh-debt-list) u0) ;; if still has debt
                      (let ((socialization-result (fold socialize-debt-asset 
                                                        fresh-debt-list 
                                                        { borrower: borrower, success: true })))
                        (asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)
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

**File:** mainnet/contracts/market/v0-market-vault.clar (L406-422)
```text
(define-public (collateral-remove (account principal) (amount uint) (ft <ft-trait>) (asset-id uint) (recipient principal))
  (let ((states (var-get pause-states))
        (entry (resolve account))
        (user-id (get id entry))
        (mask (get mask entry))
        (remaining (try! (remove-user-collateral user-id asset-id amount)))
        (updated-mask (if (is-eq remaining u0)
                        (mask-update mask asset-id true false) ;; collateral, remove
                        mask))
        (updated-entry (merge entry (refresh updated-mask))))

    (try! (check-impl-auth))
    (asserts! (not (get collateral-remove states)) ERR-PAUSED)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)

    (insert updated-entry)
    (try! (send-tokens ft amount recipient))
```
