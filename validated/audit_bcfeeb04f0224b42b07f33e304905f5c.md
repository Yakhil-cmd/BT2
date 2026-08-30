### Title
Stale liquidity index in `market.clar`'s per-block `index-cache` after `socialize-debt` mispricing zToken collateral for unrelated users in the same block - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`v0-4-market.clar` (and its `local-testing` counterpart `market.clar`) caches vault indexes in `index-cache-` keyed only by `{timestamp: stacks-block-time, aid}` [1](#0-0) . The cache is primed the *first* time any operation in a block calls `accrue-and-cache` for a given vault, and every subsequent call in the same block (regardless of caller) is served the cached value instead of the live vault state [1](#0-0) . `socialize-debt` in the vault contracts writes down `lindex` (the liquidity index used to price zTokens) directly and immediately outside of `accrue()`, without any corresponding invalidation of `market`'s `index-cache-` entry [2](#0-1) . If a liquidation that triggers bad-debt socialization primes the cache with the pre-socialization index at the *start* of its transaction and only reduces `lindex` later in the same call [3](#0-2) , any other unrelated user's transaction that touches the same vault later in the same block reads the stale, overvalued `lindex`/`index` from the cache rather than the corrected post-socialization value.

### Finding Description
`accrue-and-cache` is a per-timestamp memoization layer: on cache miss it calls `vault-accrue` (which mutates the vault's real `index`/`lindex` state variables) and stores the result under `{timestamp: stacks-block-time, aid}`; on cache hit it simply returns the previously stored value without re-checking or re-deriving it from the vault's current on-chain state [1](#0-0) .

In `liquidate`, the position's debt and collateral are accrued (and thus cached) at the very top of the function — *before* any liquidation math or socialization happens [4](#0-3) . Later in the same function, if the borrower's collateral is fully exhausted, `vault-socialize-debt` is invoked to write off bad debt [5](#0-4) , and the vault's `socialize-debt` implementation directly sets a new, lower `lindex` proportional to the loss, bypassing `accrue()` entirely [2](#0-1) .

Because the market's `index-cache-` was already populated for that `{timestamp, aid}` pair earlier in the *same* transaction, and the cache key does not distinguish "before" from "after" the socialize-debt call, the cache is left holding the outdated (higher) `lindex`. Any other transaction in the same block (same `stacks-block-time`) that subsequently calls `accrue-and-cache` for that vault — for example, a completely different borrower's `collateral-add`, `collateral-remove`, or another liquidator's `liquidate` call involving the same zToken as collateral — will hit the cache and receive the stale, pre-write-down index instead of the corrected value [6](#0-5) . Since zToken collateral value is derived from `lindex` [7](#0-6) , this causes that unrelated user's zToken collateral to be overvalued relative to the true, loss-adjusted state for the remainder of the block.

This is a shared-state bug between two unprivileged principals: the liquidator/borrower whose liquidation triggers `socialize-debt` (attacker/trigger) and any other user in the same block whose position is evaluated against the same vault's zToken collateral (victim), mediated by the shared `index-cache-` map in `market.clar`.

### Impact Explanation
Overvaluing zToken collateral for a victim's position in the same block as a socialize-debt event can let the victim's position appear healthier than it truly is. This could allow: a borrower to avoid a liquidation that should have triggered (temporary freezing of the appropriate liquidation/loss-realization for suppliers), or a liquidator to seize less collateral than the debt actually warrants because the collateral-side denominator used is inflated, or conversely let another user borrow/withdraw more than the true, loss-adjusted collateral value supports. This lands on **temporary freezing of funds / mispriced collateral within a block**, and in the worst case (a large borrow/collateral-remove executed against the inflated valuation before the next block re-derives a fresh index) contributes to under-collateralized positions that persist past the block, risking protocol insolvency for the vault's suppliers.

### Likelihood Explanation
Requires: (1) a liquidation in a block that results in `no-collateral-left` and triggers `vault-socialize-debt` for a given zToken's underlying vault, and (2) a second, independent transaction in the *same block* that touches the same vault's zToken pricing via `accrue-and-cache`/`get-cached-indexes` after the socializing transaction. Given Stacks block times and the fact that liquidations and other market operations (borrows, collateral changes, other liquidations) can be submitted to the same block by unrelated actors — including the attacker deliberately submitting a follow-up transaction in the same block to exploit their own or another's freshly-diminished vault — this is plausible but requires specific timing/ordering within a block, making likelihood moderate rather than trivial.

### Recommendation
Invalidate or refresh the `index-cache-` entry whenever `socialize-debt` (or any other operation that mutates `index`/`lindex` outside of the normal `accrue()` path) is executed on a vault, e.g., by having `vault-socialize-debt` return the updated indexes and having `market.clar` `map-set` the cache immediately after the call, or by including a monotonically increasing "epoch"/version counter in the vault's state that is included in the cache key so any out-of-band mutation invalidates cached reads for the remainder of the block.

### Proof of Concept
1. Block N: User A holds a fully-collateralized position that becomes eligible for liquidation with `no-collateral-left`.
2. Liquidator L calls `liquidate` on A's position at the start of the transaction; `accrue-user-collateral`/`accrue-and-cache` caches vault `V`'s current `{index, lindex}` for `{timestamp: T, aid: V}` [4](#0-3) .
3. Later in the same `liquidate` call, bad debt on `V` is socialized via `vault-socialize-debt`, which directly writes down `lindex` in vault `V`'s state [2](#0-1)  — but the market's cached `{T, V}` entry is never updated.
4. Still within block N (same `stacks-block-time` T), unrelated user B calls `collateral-add`/`collateral-remove`/`liquidate` involving zToken-`V` as collateral; `accrue-and-cache V` hits the stale cache and returns the pre-socialization `lindex`, overvaluing B's zToken-`V` collateral for the health check [1](#0-0) .
5. B's position passes a health check or avoids liquidation that should have failed/triggered under the corrected, loss-adjusted `lindex`.

### Citations

**File:** local-testing/contracts/market/market.clar (L253-265)
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

**File:** local-testing/contracts/market/market.clar (L1081-1093)
```text
                    (let ((current-coll-usd (get collateral current-notional))
                          (current-capacity (* current-coll-usd current-ltv))
                          ;; Prime cache for new zToken collateral underlying if not already cached
                          (cache-primed (if (is-ztoken asset-id)
                                            (let ((vault-id (if (is-eq asset-id zSTX) STX
                                                            (if (is-eq asset-id zsBTC) sBTC
                                                            (if (is-eq asset-id zstSTX) stSTX
                                                            (if (is-eq asset-id zUSDC) USDC
                                                            (if (is-eq asset-id zUSDH) USDH
                                                            (if (is-eq asset-id zstSTXbtc) stSTXbtc
                                                            u100))))))))
                                              (try! (accrue-and-cache vault-id)))
                                            { index: u0, lindex: u0 }))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L942-964)
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
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1405-1430)
```text
    ;; accrue FIRST - populates cache for zToken price resolution
    (u-debt (accrue-user-debts (get debt pos-full)))
    (u-coll (accrue-user-collateral (get collateral pos-full)))

    ;; NOW safe to resolve prices (cache is populated)
    (assets (get-assets mask))
    (notional-valued-assets (get-notional-evaluation { position: position, assets: assets }))
    (total-collateral-usd (get collateral notional-valued-assets))
    (total-debt-usd (get debt notional-valued-assets))

    ;; LTC thresholds, liq params, health
    (ltv-liq-partial (buff-to-uint-be (get LTV-LIQ-PARTIAL group)))
    (ltv-liq-full (buff-to-uint-be (get LTV-LIQ-FULL group)))
    (liq-penalty-min (buff-to-uint-be (get LIQ-PENALTY-MIN group)))
    (liq-penalty-max (buff-to-uint-be (get LIQ-PENALTY-MAX group)))
    (curve-exponent (buff-to-uint-be (get LIQ-CURVE-EXP group)))

    ;; LTV = (debt x 10,000) / collateral
    ;; handle edge case: If collateral = 0, return max LTV (BPS) or 0 if debt also 0
    (current-ltv   (if (is-eq total-collateral-usd u0)
                       (if (is-eq total-debt-usd u0) u0 BPS)
                       (mul-div-down total-debt-usd BPS total-collateral-usd)))
    
    ;; Oracle frontrunning protection: prevent same-block liquidation
    ;; This blocks flash-loan based attacks where user borrows + gets liquidated in same block
    (last-borrow-block (get last-borrow-block position))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1496-1524)
```text
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
```

**File:** docs/vaults.md (L549-561)
```markdown

```
