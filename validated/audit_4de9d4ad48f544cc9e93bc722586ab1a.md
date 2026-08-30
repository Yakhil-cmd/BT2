### Title
Stale timestamp-keyed index cache lets a socialize-debt write-down be bypassed for other users' health checks in the same block - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
`v0-4-market.clar` caches vault liquidity/borrow indexes in `index-cache` keyed only by `{ timestamp: stacks-block-time, aid }` [1](#0-0) . Once any user's transaction primes this cache for a given asset in a block, every subsequent call in the same block reuses that cached `{index, lindex}` pair via `accrue-and-cache` cache-hit path instead of re-deriving it from the vault, and `resolve-ztoken`/`get-cached-indexes` use that same cached pair to price zToken collateral for health checks, borrows, and liquidations [2](#0-1) .

### Finding Description
`accrue-and-cache` is a cache-first wrapper: on a cache hit it returns the previously stored `{index, lindex}` for `(stacks-block-time, aid)` without calling `vault-accrue` again [1](#0-0) . `vault-socialize-debt` is a distinct market wrapper that routes directly to the vault's `socialize-debt` entry point [3](#0-2) , which is the mechanism that write-down a vault's share value/liquidity index to absorb bad debt discovered during liquidation. This call path does not go through `accrue-and-cache`, so it does not refresh or invalidate the `index-cache` entry for that asset in the current block.

Sequence:
1. Attacker/first user A performs any operation touching vault `aid=X` (e.g. a deposit or repay) earlier in block `T`. This calls `accrue-and-cache`, which computes fresh `{index, lindex}` and stores it under key `{timestamp: T, aid: X}` [1](#0-0) .
2. Still in block `T`, a liquidation on a different position triggers `vault-socialize-debt` for `aid=X`, which writes a lower true liquidity index into the vault to reflect the newly-recognized bad debt [3](#0-2) . The market's `index-cache` entry for `(T, X)` is untouched and remains at the pre-write-down value.
3. Later in the same block `T`, user B — holding `zX` (vault-X shares) as collateral — triggers a borrow or is evaluated for liquidation. Pricing for `zX` goes through `resolve-ztoken`, which calls `get-cached-indexes(X)` and gets the stale, pre-socialization `lindex` still cached under `(T, X)` [2](#0-1) .

The victim's outcome differs from the counterfactual: without the earlier cache-priming transaction, B's `zX` collateral would be repriced against the vault's true post-socialization index (lower, correctly reflecting the loss), and B's health check would either block the borrow or trigger correct liquidation. With the stale cache, B's collateral is overvalued for the remainder of the block, letting B borrow beyond their real backing or escape liquidation — pushing uncollateralized risk onto the rest of the pool/protocol.

### Impact Explanation
Overvaluing collateral due to a stale shared cache lets a position remain "healthy" or under-liquidated when it should not be, increasing unrecognized bad debt that is ultimately socialized across all suppliers of that vault — this is a protocol-insolvency-adjacent impact (in-scope: protocol insolvency / permanent freezing of funds for suppliers whose claims are diluted by the extra bad debt that should have been caught).

### Likelihood Explanation
Requires a socialize-debt event (bad-debt write-down) to occur in the same block as both a prior cache-priming transaction and a later borrow/health-check on the same asset by a different user. This is a timing/ordering dependency rather than something the attacker can freely trigger, but socialize-debt is a routine part of the liquidation path (not an admin-only rare event), and any user could opportunistically front-run/back-run within the same block once they observe a pending liquidation, so likelihood is non-trivial but conditional on same-block ordering.

### Recommendation
Invalidate or refresh the `index-cache` entry for an asset whenever `vault-socialize-debt` is invoked for that asset in the same block, or have `socialize-debt` write its updated indexes into `index-cache` directly so subsequent reads in the block are consistent, rather than relying purely on the `(timestamp, aid)` key which only accounts for time-based accrual and not out-of-band index adjustments.

### Proof of Concept
Not independently executable from static review alone — this analysis is based on the cache-priming/read pattern in `accrue-and-cache`, `get-cached-indexes`, and `resolve-ztoken`, and the separate `vault-socialize-debt` call path in `v0-4-market.clar`, cited above. I was not able to fully inspect the vault-side `socialize-debt` implementation (e.g. `mainnet/contracts/vault/v0-vault-stx.clar`) before running out of tool iterations to confirm exactly which index fields it mutates and whether any other invalidation of the market's `index-cache` map occurs elsewhere; this should be verified directly in the vault contracts before treating this as fully proven.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L216-223)
```text
(define-private (vault-socialize-debt (aid uint) (amount uint))
  (if (is-eq aid STX) (contract-call? .v0-vault-stx socialize-debt amount)
  (if (is-eq aid sBTC) (contract-call? .v0-vault-sbtc socialize-debt amount)
  (if (is-eq aid stSTX) (contract-call? .v0-vault-ststx socialize-debt amount)
  (if (is-eq aid USDC) (contract-call? .v0-vault-usdc socialize-debt amount)
  (if (is-eq aid USDH) (contract-call? .v0-vault-usdh socialize-debt amount)
  (if (is-eq aid stSTXbtc) (contract-call? .v0-vault-ststxbtc socialize-debt amount)
  ERR-UNKNOWN-VAULT)))))))
```

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

**File:** mainnet/contracts/market/v0-4-market.clar (L343-347)
```text
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
```
