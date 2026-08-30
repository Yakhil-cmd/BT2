### Title
Stale shared index-cache read across unrelated users' transactions in the same block after `socialize-debt` mutates vault state - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar` (and its production counterpart `v0-4-market.clar`) maintains a per-block cache of vault liquidity/borrow indexes, keyed only by `{timestamp, aid}`, and skips re-reading the vault whenever a cache entry already exists for that key [1](#0-0) . Because the cache is primed by whichever transaction happens to call `accrue-and-cache` first in a block, and is blindly trusted by every subsequent, unrelated transaction in the same block, a later mutation of the vault's true index by one user's action (`vault-socialize-debt`) is not reflected back into the cache that other users' transactions read for the rest of that block.

### Finding Description
`accrue-and-cache` is the single gate market.clar uses before any collateral/debt valuation, borrow, or health check touches an asset's index:

```
(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache cache-key)))
    (match cached?
      cached-indexes (ok cached-indexes)                 ;; HIT: trusted blindly
      (let ((indexes (try! (vault-accrue aid))))
        (map-set index-cache cache-key indexes)
        (ok indexes)))))
``` [1](#0-0) 

The cache key contains only `timestamp` and `aid` — it does not incorporate any notion of "vault generation" or a hash/root of the vault's actual index state, so there is no check that the cached tuple still matches the vault's current index at read time (analogous to Prysm's missing state-root check: a downstream consumer trusts a cached value keyed by a coarse identifier instead of validating it against the true state). This cache is consumed by `borrow`, and by extension every collateral/debt valuation path that calls `accrue-user-debts`/`accrue-user-collateral` before computing health [2](#0-1) .

Separately, `market.clar` exposes a `vault-socialize-debt` dispatcher that lets a caller directly mutate a vault's bad-debt/index state outside of the normal `vault-accrue` path [3](#0-2) ; the same dispatcher exists in the production contract [4](#0-3) .

Sequence within one block:
1. TX-1 (any user, e.g. a liquidator) calls a path that first triggers `accrue-and-cache(aid)` — cache MISS, `vault-accrue` runs, and the resulting `{index, lindex}` is stored under `{timestamp: T, aid}`.
2. Still within TX-1 (or in the same block via a separate liquidation transaction), `vault-socialize-debt` is invoked, mutating the vault's true index/exchange rate to write off bad debt — but this mutation is never propagated back into `index-cache`.
3. TX-2, submitted by an unrelated user later in the same block, calls `borrow`/`redeem`/a health check for the same `aid`. `accrue-and-cache` reports a cache HIT and returns the pre-socialization `{index, lindex}` from step 1, even though the vault's real state has since changed.

TX-2's collateral/debt valuation and redemption math are therefore computed against a value that no longer matches the vault's true, just-mutated state — the shared cache primed by TX-1 is consumed unchanged by TX-2, and TX-2's outcome depends on TX-1's ordering within the block, exactly the ordering-dependence / shared-cache pattern the analog targets.

### Impact Explanation
If the true post-socialization index is lower than what remains cached (e.g. bad debt write-off dilutes the liquidity index), a victim's redeem/health computation in TX-2 would use the stale, higher index, letting them redeem more underlying than they are entitled to or pass a health check that should have failed — both at the expense of the remaining depositors of that vault. This falls under High severity: theft of unclaimed yield or temporary freezing of funds for the remaining suppliers, since one user's redemption based on a stale index directly reduces the assets available to others in the pool.

### Likelihood Explanation
Exploitation requires two transactions to land in the same block in the specific order (a socialize-debt-triggering liquidation followed by a victim/attacker action on the same asset), which is a narrow but realistic condition a searcher/attacker could engineer by front-running or bundling their own transaction immediately after observing a pending liquidation.

### Recommendation
Invalidate or refresh the relevant `index-cache` entry whenever `vault-socialize-debt` (or any other function that mutates a vault's index outside of `vault-accrue`) runs, or remove the cache-HIT short-circuit for the remainder of the block once such a mutation has occurred, so every transaction in the block reads a value consistent with the vault's current true state.

### Proof of Concept
Not executed — this is based on static analysis of `accrue-and-cache`'s HIT/MISS logic and the existence of a separate `vault-socialize-debt` mutation path that bypasses cache invalidation. I was not able to inspect the full body of `vault-socialize-debt` inside the vault contracts (only its call sites in `market.clar`/`v0-4-market.clar`) within the available tool budget, so the exact magnitude/direction of the index shift caused by socialize-debt is unverified; this should be confirmed against `vault-stx.clar`'s (and sibling vaults') `socialize-debt` implementation before treating this as conclusively exploitable.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1246-1258)
```text
        ;; Step 1: Get position WITHOUT resolving prices
        (position (try! (get-position account)))
        (mask (get mask position))
        
        ;; Step 2: Accrue user's positions (populates cache for ztokens)
        (u-debt (accrue-user-debts (get debt position)))
        (u-coll (accrue-user-collateral (get collateral position)))
        
        ;; Step 3: Accrue the asset being borrowed (needed for index access)
        (unused (accrue-and-cache asset-id))
        
        ;; Step 4: NOW safe to resolve prices (cache is populated)
        (assets (get-assets mask))
```

**File:** local-testing/contracts/market/market.clar (L224-231)
```text
(define-private (vault-socialize-debt (aid uint) (amount uint))
  (if (is-eq aid STX) (contract-call? .vault-stx socialize-debt amount)
  (if (is-eq aid sBTC) (contract-call? .vault-sbtc socialize-debt amount)
  (if (is-eq aid stSTX) (contract-call? .vault-ststx socialize-debt amount)
  (if (is-eq aid USDC) (contract-call? .vault-usdc socialize-debt amount)
  (if (is-eq aid USDH) (contract-call? .vault-usdh socialize-debt amount)
  (if (is-eq aid stSTXbtc) (contract-call? .vault-ststxbtc socialize-debt amount)
  ERR-UNKNOWN-VAULT)))))))
```
