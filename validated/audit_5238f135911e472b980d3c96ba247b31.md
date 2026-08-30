### Title
Stale market-level index/lindex cache after `socialize-debt` overvalues zToken collateral for other users in the same block - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
`v0-4-market.clar` caches each vault's `{index, lindex}` in `index-cache-` keyed only by `{timestamp, aid}` via `accrue-and-cache`, and reuses the cached entry for every subsequent operation in the same block (same `stacks-block-time`) without re-querying the vault [1](#0-0) . This caching assumes a vault's `lindex`/`index` only change due to time-based interest accrual, which is idempotent within one timestamp. However, `liquidate` can trigger `vault-socialize-debt`, which directly rewrites a vault's `lindex` downward to account for bad debt, independent of elapsed time [2](#0-1) . If the market already cached that vault's indexes earlier in the same block (e.g., from any user's borrow/collateral operation touching that zToken), any other user's transaction later in the same block that reuses the market cache will value that vault's zToken collateral using the pre-socialization (stale, too high) `lindex`.

### Finding Description
- `accrue-and-cache` in the market contract caches vault indexes per `(timestamp, aid)` and returns the cached value on any subsequent hit within the same block, skipping a fresh vault read: [1](#0-0) .
- `liquidate` performs `vault-system-repay`, then (if the borrower has no collateral left) folds `socialize-debt-asset` over the borrower's remaining debt list, invoking `vault-socialize-debt` for the relevant asset id: [3](#0-2) .
- `socialize-debt` in the vault directly overwrites `lindex` based on the loss versus `total-assets`, bypassing the market's `index-cache-` entirely: [2](#0-1) .
- zToken (rehypothecated) collateral valuation elsewhere in the market relies on `get-cached-indexes`/the cached `lindex` for that vault's aid, e.g., when priming cache for new collateral or resolving debt/collateral notional values in `borrow`, `collateral-add`, and `liquidate` itself: [4](#0-3) [5](#0-4) .

Sequence within one block (same `stacks-block-time`):
1. User A (or the liquidator's own prior collateral accrual step) causes `accrue-and-cache` to be called for vault X, caching `{index, lindex}` at the current timestamp.
2. A liquidation of some other borrower with no collateral left triggers `vault-socialize-debt` on vault X, which lowers vault X's real `lindex` (writing off bad debt against zToken-X holders) but never touches the market's `index-cache-` map.
3. User B, in the same block, performs a market operation involving zToken-X collateral (e.g., `borrow`, `collateral-add`). `accrue-and-cache` for vault X hits the stale cache entry from step 1 and returns the pre-socialization, inflated `lindex`.
4. User B's zToken-X collateral is valued using the stale, too-high `lindex`, letting B borrow against collateral that is actually worth less (post-write-down), or pass health checks that should fail.

### Impact Explanation
This lets an unrelated, unprivileged user (B) obtain excess borrowing capacity against overvalued zToken collateral immediately after another user's liquidation socializes bad debt in the same block. The loss from B's excess borrowing that is not truly collateralized is ultimately socialized across all vault suppliers, matching the "socialization charged to all suppliers" / protocol-insolvency impact class (Critical: protocol insolvency due to under-collateralized debt being created against a stale, inflated collateral valuation).

### Likelihood Explanation
Requires: (a) a liquidation in the same block that triggers bad-debt socialization (`no-collateral-left` branch) for a zToken-backed vault, (b) that vault's index already cached earlier in the block, and (c) another user performing a zToken-collateral-valuing operation later in the same block. All three actors are unprivileged; ordering within a block can be influenced via transaction fee/ordering (a known lever on Stacks), making this a realistic same-block ordering-dependence scenario rather than a purely theoretical one.

### Recommendation
Invalidate or refresh the market's `index-cache-` entry for a vault whenever `vault-socialize-debt` is invoked on that vault within the same transaction, or have `socialize-debt` return updated indexes that the market immediately re-caches (`map-set index-cache- {timestamp, aid} fresh`) instead of leaving the previous cached entry in place for the rest of the block.

### Proof of Concept
1. Block N, tx 1: Any user interacts with the market touching zToken-X collateral (e.g., `collateral-add`/`borrow`), causing `accrue-and-cache` to cache vault X's `{index, lindex}` for `(timestamp=T, aid=X)`.
2. Block N, tx 2: Liquidator liquidates borrower C, whose position has no collateral left, causing the market to call `vault-socialize-debt` on vault X, reducing vault X's on-chain `lindex` to reflect the write-off (per `mainnet/contracts/vault/v0-vault-sbtc.clar:946-968`).
3. Block N, tx 3: User B calls `borrow`/`collateral-add` using zToken-X as collateral. `accrue-and-cache` returns the cache entry set in tx 1 (pre-write-down `lindex`), so B's zToken-X collateral is valued higher than its true post-socialization worth, letting B borrow more than the collateral actually backs.
4. Verification would require confirming, in a fork/test harness, that `get-cached-indexes`/`accrue-and-cache` indeed return the stale entry after `socialize-debt` runs later in the same block — this exact interaction was not runnable in this analysis; only static code paths were traced.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1051-1070)
```text
                    (current-assets (get-assets current-mask))
                    (current-notional (get-notional-evaluation { position: position, assets: current-assets }))
                    (current-debt-usd (get debt current-notional)))

                ;; ONLY check capacity if user has debt
                (if (> current-debt-usd u0)
                    ;; Calculate future mask and validate egroup exists
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1291-1291)
```text
          (borrow-index (get index (unwrap-panic (get-cached-indexes asset-id)))))
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

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L946-968)
```text
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

    (print {
      action: "socialize-debt",
      caller: contract-caller,
```
