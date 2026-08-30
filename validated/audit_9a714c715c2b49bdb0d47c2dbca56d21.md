### Title
Block-scoped index cache lets one user's transaction determine stale/manipulated interest and liquidity indexes consumed by every other user's collateral, debt, and liquidation checks in the same block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar`'s `accrue-and-cache` function memoizes each vault's borrow index and liquidity index (`lindex`) in a map keyed **only** by `{ timestamp: stacks-block-time, aid: <asset-id> }`, with no dependency on `tx-sender` or the specific transaction. The first transaction that touches a given asset in a block computes the fresh index via `vault-accrue` and writes it to `index-cache`; every subsequent, unrelated transaction that touches the same asset in the same block reads that cached value instead of recomputing it [1](#0-0) . This is a shared cache primed by one caller and consumed by another - exactly the pattern in scope.

### Finding Description
`accrue-and-cache` is invoked from every position-mutating and health-check path (`collateral-add`, `borrow`, liquidation, etc.) via `accrue-user-debts`/`accrue-user-collateral`, and the cached value is later read through `get-cached-indexes` for pricing, health checks, and liquidation math [2](#0-1) [3](#0-2) .

Because the cache key contains only the block timestamp and the asset id, the *first* caller in a block that triggers an accrual for asset `X` permanently fixes the index used by every other unrelated user's operation on asset `X` for the rest of that block - even if the true, on-chain utilization/rate conditions changed moments earlier or later within the same block due to that first caller's own deposit/withdraw activity. The protocol's own liquidation-socialization code demonstrates that developers are aware the cache can go stale mid-block: `socialize-debt-asset` explicitly re-runs `vault-accrue` and overwrites `index-cache` immediately after a debt write-down, with the comment "Refresh cache with new indexes post-write-down (lindex decreased)" [4](#0-3) . This patch only covers the socialize-debt path; no equivalent refresh exists for ordinary deposit/withdraw/borrow/repay flows that also change vault utilization and thus the rate used by `vault-accrue`.

Attack shape: attacker A performs a large deposit/withdraw on vault `X` to swing utilization to an extreme value, then makes a minimal call (e.g., `collateral-add` for 1 unit) that triggers `accrue-and-cache` for `X`, locking in an index computed from the manipulated instantaneous utilization for the rest of the block. A then reverses the swing (withdraws/re-deposits) in the same block. Any other, unrelated user B whose position also references asset `X` (as debt or as a ztoken collateral whose value depends on `lindex`) and who transacts later in the same block - or whose position is evaluated by a liquidator in the same block - has their debt/collateral valued using A's poisoned index rather than the true one.

### Impact Explanation
- If A drives the index down before caching it, other borrowers' debt in `X` is understated for the remainder of the block: liquidators evaluating those unrelated positions via `get-cached-indexes` will see an artificially healthy position and be unable to liquidate genuinely undercollateralized debt in that block, and borrowers could pass health checks (`ERR-UNHEALTHY` assertions in `collateral-add`/`borrow`) that should have failed, allowing them to extract more borrow capacity than their real collateral supports - a path to protocol insolvency.
- If A drives the index up before caching it, another unrelated user's ztoken collateral or debt priced off the poisoned `lindex`/index can be mis-valued upward or downward, causing incorrect liquidation eligibility or seizure amounts for a victim who did nothing but hold a position in the affected asset during that block.

This lands in the Critical impact bucket (protocol insolvency via mispriced debt / theft of funds at rest through wrongful liquidation avoidance or wrongful seizure) rather than the excluded "ordinary shared-pool economics" category, because the harm flows specifically through a stale, attacker-primed cache entry consumed by a different principal's position evaluation, not through normal pool-wide rate movement that all suppliers accept as design.

### Likelihood Explanation
Every position-mutating call in `market.clar` (`collateral-add`, `borrow`, `collateral-remove`, liquidation) triggers `accrue-and-cache`, so the cache is written on nearly every block that has any market activity on a given asset, giving an attacker many chances to be "first" in a block. The exact sensitivity of `vault-accrue`'s rate model to instantaneous utilization (i.e., whether the interest/liquidity index computation reads a spot utilization number that a same-block deposit/withdraw can swing) could not be fully confirmed from the snippets retrieved — this needs to be verified directly against each `vault-*.clar` contract's `accrue`/`system-borrow`/`system-repay` implementation to size the realistic magnitude of index manipulation achievable within one block. The known, dev-acknowledged staleness fix in `socialize-debt-asset` is strong circumstantial evidence that mid-block cache staleness is a real, previously-identified correctness gap that was only partially patched.

### Recommendation
Key `index-cache` by a monotonically increasing operation counter (or invalidate/refresh it on every state-mutating vault call, not just `socialize-debt-asset`), so that no transaction within a block can read an index that predates a same-block state change to the underlying vault. Alternatively, remove the cross-transaction caching optimization entirely and always recompute `vault-accrue` fresh per call, accepting the extra cross-contract calls, or bound the rate model so within-block utilization swings cannot materially move the cached index.

### Proof of Concept
1. Block N, tx 1 (attacker A): large `deposit` into `vault-X` to push utilization far from its steady-state value.
2. Block N, tx 2 (attacker A): `collateral-add` (or any minimal call) touching asset `X`, causing `accrue-and-cache` to call `vault-accrue X` and write the resulting index/`lindex` into `index-cache` keyed by `{ timestamp: stacks-block-time, aid: X }` [1](#0-0) .
3. Block N, tx 3 (attacker A): reverse the deposit (`redeem`/withdraw), returning `vault-X` utilization to normal.
4. Block N, tx 4 (unrelated victim or liquidator): calls `borrow`, `collateral-add`, or a liquidation path that reads `get-cached-indexes X` [3](#0-2)  — this call reuses A's poisoned index rather than recomputing from true current state, mispricing the victim's debt/collateral for the remainder of block N.

Note: full confirmation of the magnitude of index manipulation achievable via a single-block utilization swing requires inspecting the `accrue`/rate-model implementation inside each `vault-*.clar` contract, which was not fully retrievable within this investigation's scope.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L245-257)
```text
(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache cache-key)))

    (match cached?
      ;; cache HIT: return cached value (1 read only)
      cached-indexes (ok cached-indexes)

      ;; cache MISS: accrue and cache (vault-accrue now returns indexes)
      (let ((indexes (try! (vault-accrue aid))))
        ;; store in cache
        (map-set index-cache cache-key indexes)
        (ok indexes)))))
```

**File:** local-testing/contracts/market/market.clar (L253-300)
```text
(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache cache-key)))

    (match cached?
      ;; cache HIT: return cached value (1 read only)
      cached-indexes (ok cached-indexes)

      ;; cache MISS: accrue and cache (vault-accrue now returns indexes)
      (let ((indexes (try! (vault-accrue aid))))
        ;; store in cache
        (map-set index-cache cache-key indexes)
        (ok indexes)))))

(define-private (accrue-user-debts (debt-list (list 64 { aid: uint, scaled: uint})))
  (fold accrue-debt-asset debt-list { success: true }))

(define-private (accrue-debt-asset
  (debt-entry { aid: uint, scaled: uint })
  (acc { success: bool }))
  (begin
    ;; this will use cache if available, accrue if not
    (unwrap-panic (accrue-and-cache (get aid debt-entry)))
    acc))

(define-private (accrue-user-collateral (coll-list (list 64 {aid: uint, amount: uint})))
  (fold accrue-collateral-asset coll-list { success: true }))

(define-private (accrue-collateral-asset
  (coll-entry { aid: uint, amount: uint })
  (acc { success: bool }))
  (let ((aid (get aid coll-entry)))
    ;; Only accrue if asset is a registered ztoken
    (if (is-ztoken aid)
        ;; ZToken: map to underlying vault routing ID and accrue
        ;; zSTX(1)->STX(0), zsBTC(3)->sBTC(2), zstSTX(5)->stSTX(4), zUSDC(7)->USDC(6), zUSDH(9)->USDH(8), zstSTXbtc(11)->stSTXbtc(10)
        (let ((vault-id (if (is-eq aid zSTX) STX
                        (if (is-eq aid zsBTC) sBTC
                        (if (is-eq aid zstSTX) stSTX
                        (if (is-eq aid zUSDC) USDC
                        (if (is-eq aid zUSDH) USDH
                        (if (is-eq aid zstSTXbtc) stSTXbtc
                        ;; Should never reach here if is-ztoken is correct
                        ;; but if reached will cause ERR-UNKNOWN-VAULT with any value over 64
                        u100))))))))
          (begin
            (unwrap-panic (accrue-and-cache vault-id))
            acc))
```

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

**File:** local-testing/contracts/market/market.clar (L966-967)
```text
(define-read-only (get-cached-indexes (aid uint))
  (map-get? index-cache { timestamp: stacks-block-time, aid: aid }))
```
