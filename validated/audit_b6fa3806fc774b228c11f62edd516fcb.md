## Analysis

Zest's `market.clar` maintains a **block-scoped index cache** (`index-cache-`/`index-cache`) keyed by `{ timestamp: stacks-block-time, aid: aid }` that stores each vault's `{index, lindex}`. The cache is populated the first time any user's transaction in a block touches a given vault (via `accrue-and-cache`), and every subsequent transaction *in the same block* reads the cached value instead of re-querying the vault: [1](#0-0) 

That cached `lindex` is what the oracle/health-check logic uses to price ztoken (rehypothecated) collateral and to convert vault shares to underlying value for the rest of the block: [2](#0-1) 

However, `socialize-debt` — invoked by the liquidation flow through `market.clar`'s `vault-socialize-debt` dispatcher — writes a new, lower `lindex` **directly** into the vault's own state, entirely bypassing `market.clar`'s `index-cache`: [3](#0-2) [4](#0-3) 

Because `stacks-block-time` is identical for every transaction in a block, once `accrue-and-cache` has been primed for a vault (e.g., by an earlier deposit/borrow/health-check in the block), a later `socialize-debt` call (triggered by a bad-debt liquidation) updates the vault's real `lindex` downward but leaves the market's cached `{index, lindex}` for that block untouched. Any *other* user's transaction later in the same block that relies on `accrue-and-cache`/`get-cached-indexes` for that asset (health checks, zToken pricing, redemption previews) will keep reading the stale, pre-loss (higher) `lindex` instead of the corrected post-socialization value.

### Title
Stale block-scoped `index-cache` after `socialize-debt` lets later users in the same block use a pre-loss liquidity index — (File: `market/market.clar`)

### Summary
`market.clar` caches each vault's `{index, lindex}` once per block, keyed only by `{timestamp: stacks-block-time, aid}`. `socialize-debt`, which write-downs a vault's `lindex` to socialize a bad-debt loss across suppliers, is called directly on the vault and never updates or invalidates this cache. If the cache was already primed earlier in the block, every subsequent transaction in that same block continues to see the pre-loss `lindex`.

### Finding Description
- `accrue-and-cache` in `market.clar` caches vault indexes on cache-key `{stacks-block-time, aid}` and reuses the cached value for all calls within the block: [1](#0-0) 
- `vault-socialize-debt` routes straight to each vault's `socialize-debt` entry point with no interaction with `market.clar`'s cache map: [3](#0-2) 
- `socialize-debt` in the vault mutates `lindex` (and `principal-scaled`/`total-borrowed`/`assets`) directly in vault storage: [4](#0-3) 
- The cached `lindex` is the value used across the block for ztoken price resolution / collateral valuation, per the documented design: [5](#0-4) 

**Attacker/victim/shared-state mapping:** the shared state is the `index-cache` map in `market.clar`. Any unprivileged user (User A) whose ordinary transaction triggers `accrue-and-cache` primes the cache for a vault early in the block. A liquidator then calls `socialize-debt` on that vault later in the same block, lowering the real `lindex` to reflect a bad-debt loss that should be shared by all suppliers of that vault. A third unprivileged user (User B), acting later in the same block, calls any market operation that reads the cache (e.g., withdrawing zSTX, or having zSTX as collateral evaluated for a borrow/health check) and receives the stale, higher pre-loss `lindex` instead of the corrected one.

### Impact Explanation
Victim's outcome without the attacker/ordering event: User B's zToken redemption value / collateral valuation reflects the vault's true post-loss `lindex`, meaning User B bears their proportional share of the socialized loss like every other supplier.

Victim's outcome with the ordering event present (socialize-debt landing between cache-priming and User B's transaction): User B's redemption/collateral valuation still uses the stale, higher pre-loss `lindex`, letting User B redeem zTokens for more underlying value than they are entitled to post-loss, or pass a health check that should have failed — effectively pulling value that other, later-settling suppliers must absorb instead. This is a socialization charged to all suppliers that one specific, favorably-timed user evades, at the expense of the remaining supplier pool — theft of unclaimed yield/share value from other suppliers.

### Likelihood Explanation
This requires no privileged access or DAO action — only ordinary use of `market.clar`'s public deposit/borrow/redeem/liquidate entry points in the natural sequence that already occurs in production use (a normal user operation priming the cache, followed by a liquidation with socialized debt, followed by another normal user operation) within one Stacks block. The conditions (cache already primed for the asset, and a socialize-debt event for that same asset in the same block) are plausible whenever bad debt is liquidated in an active vault.

### Recommendation
Have `vault-socialize-debt` (or the vault's `socialize-debt` function itself) invalidate or refresh `market.clar`'s `index-cache-` entry for the affected `aid` at `{stacks-block-time, aid}` immediately after the write-down, so subsequent same-block reads observe the corrected `lindex`/`index` rather than the pre-loss cached value.

### Proof of Concept
1. User A calls any market operation (e.g., `deposit`) touching `vault-stx`, causing `accrue-and-cache` to cache `{index, lindex}` for `{stacks-block-time, STX}` — [1](#0-0) .
2. In the same block, a liquidator triggers a liquidation that calls `vault-socialize-debt` for `STX`, which calls `.vault-stx socialize-debt`, writing a lower `lindex` directly into vault state — [4](#0-3) .
3. Still within the same block, User B calls a market operation that reads `get-cached-indexes`/`accrue-and-cache` for `STX` (e.g., valuing zSTX collateral or redeeming zSTX) — [1](#0-0) . Because the cache entry already exists for that block's timestamp/aid, User B's transaction returns the stale pre-loss `lindex`, valuing zSTX/collateral higher than its true post-socialization worth.

### Citations

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

**File:** docs/oracle.md (L332-357)
```markdown
## Index Caching

The market maintains a timestamp-based cache for vault liquidity indexes to optimize ztoken price resolution:

```clarity
;; In market.clar
(define-map index-cache- 
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })

(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache- cache-key)))
    (match cached?
      existing existing
      (let ((fresh (vault-accrue aid)))
        (map-set index-cache- cache-key fresh)
        fresh))))
```

**Purpose:** 
- Multiple price resolutions for the same vault within a single block use cached indexes
- Avoids redundant cross-contract calls to vaults
- Significantly reduces gas costs for transactions involving multiple ztoken prices

**Cache Invalidation:** Cache is timestamp-based using `stacks-block-time`, automatically invalidating when a new block is processed.
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L944-967)
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

**File:** docs/vaults.md (L295-320)
```markdown
## Index Caching in Market

The market contract caches vault indexes per timestamp to avoid redundant vault calls within the same block:

```clarity
;; In market.clar
(define-map index-cache- 
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })

(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid }))
    ;; Check cache first, accrue vault if needed
    (match (map-get? index-cache- cache-key)
      existing existing
      (let ((fresh (vault-accrue aid)))
        (map-set index-cache- cache-key fresh)
        fresh))))
```

**Benefits:**
- Multiple operations on same vault in one block use cached index
- Reduces cross-contract calls significantly
- Lower gas costs for complex transactions
- Cache automatically invalidates next block (timestamp changes)

```
