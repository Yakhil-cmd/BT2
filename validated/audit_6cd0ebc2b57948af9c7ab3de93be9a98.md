### Title
Stale index-cache after debt socialization causes mispriced ztoken collateral within the same block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`v0-4-market.clar` maintains a per-block, per-asset cache of vault interest indexes (`index-cache`) that is *shared across all callers* in the same block. `accrue-and-cache` only refreshes this cache on a cache-miss; on a hit it returns whatever was stored earlier in the block, without re-checking whether the vault's underlying `lindex` has since changed. The vault's `socialize-debt` function (called during bad-debt write-off/liquidation) directly mutates the vault's `lindex` via `(var-set lindex new-lindex)` but never goes through `accrue-and-cache`, so it never refreshes or invalidates the market-level cache. This is analogous to the DODO report's root cause — a check/settlement path silently diverging from the state actually produced by the swap — except here the divergent, stale value is a *shared cache primed by one caller and consumed by another*, which the task rules explicitly flag as an in-scope analog class.

### Finding Description
`accrue-and-cache` in `v0-4-market.clar` is the single gate used by every collateral/debt valuation path (borrow, withdraw, collateral-add/remove, liquidation, health checks) to obtain a vault's `{index, lindex}`: [1](#0-0) 

It is keyed only by `{ timestamp: stacks-block-time, aid }`, i.e. one shared slot per asset per block, populated by whichever transaction happens to touch that asset first in the block: [2](#0-1) 

This cached value is consumed for ztoken (rehypothecated) collateral revaluation of *any* user's position later in the same block: [3](#0-2) 

The documentation asserts the cache "eliminates stale data risks" because it invalidates every new block: [4](#0-3) 

That claim only holds if every state-mutating event that affects `index`/`lindex` inside a block routes back through `accrue-and-cache`. However, `socialize-debt` (a bad-debt/liquidation mechanism) writes a *new* `lindex` directly to vault storage without touching the market's `index-cache` map, e.g. in `v0-vault-sbtc.clar`: [5](#0-4) 

Consequence: if any transaction earlier in the block already caused `accrue-and-cache` to populate the cache for that `aid` (a cache HIT scenario is by far the common case since most user actions touch popular assets like `zsBTC`/`sBTC`), and a subsequent transaction in the *same block* triggers `socialize-debt` on that vault (reducing `lindex` to reflect written-off bad debt), the vault's true `lindex` drops but the market's cached `lindex` for that `{timestamp, aid}` remains the pre-socialization value. Every other user's collateral/health-check operation that executes afterward in that same block will read the stale, higher cached `lindex` via `accrue-and-cache`'s cache-HIT branch, overvaluing their zToken collateral relative to the asset's real backing.

### Impact Explanation
This is a cross-user (attacker vs. victim/protocol) impact, not a self-only issue:
- A borrower whose position becomes unhealthy immediately after a same-block `socialize-debt` event can still pass the health check (using the stale, overvalued cached `lindex`), letting them borrow more or evade liquidation they should be subject to — this understates protocol risk and can lead to insolvency (uncollateralized debt) once the true, lower `lindex` is honored in the next block.
- Conversely, any legitimate liquidation that computes collateral seizure/repay amounts off the stale cached index during the same block miscalculates against the socialized (already-adjusted) debt state, producing incorrect seizure amounts for a borrower/liquidator pair that had no part in causing the staleness.

Because the harmed party (any user whose collateral/health/liquidation calculation is evaluated later in the block) is distinct from the party that triggers the socialization, and the outcome is either protocol insolvency exposure or unfair liquidation seizure, this lands in the **Critical – protocol insolvency** / **High – temporary freezing/mispricing of funds** category.

### Likelihood Explanation
Likelihood is moderate-to-high: `socialize-debt` is a normal, permissionless-triggerable consequence of liquidation flows (not a privileged/DAO-only action), and the `index-cache` is populated opportunistically by ordinary user activity (any borrow, deposit, withdraw, or collateral operation on a popular asset primes the cache for the rest of the block). No special timing manipulation beyond "act in the same block after a socialize-debt event" is required, which is realistic on Stacks given multiple transactions can land in one block.

### Recommendation
Have `socialize-debt` (and any other vault function that mutates `index`/`lindex` outside of `accrue`) invalidate or update the corresponding `index-cache` entry in `market.clar` for the current `stacks-block-time`/`aid`, or have `accrue-and-cache` re-verify the cached value against the vault's live `lindex`/`index` (e.g., via a cheap read-only call) rather than trusting a same-timestamp cache hit unconditionally. Alternatively, have `socialize-debt` itself write back the fresh indexes into `index-cache` so subsequent same-block reads are consistent.

### Proof of Concept
Conceptual sequence (Clarity, within a single block/`stacks-block-time`):
1. User A performs any ordinary operation (e.g., `borrow`/`collateral-add`) on asset `sBTC`, causing `accrue-and-cache` to cache-MISS, call `vault-accrue`, and store `{index, lindex}` for `{timestamp: T, aid: sBTC}` in `market.index-cache`. [1](#0-0) 
2. A liquidation of a bad-debt position triggers `.v0-vault-sbtc socialize-debt`, which directly sets a new, lower `lindex` in the vault, reflecting the write-off — but never touches `market.index-cache`. [5](#0-4) 
3. User B, still within timestamp `T`, performs a `borrow` using `zsBTC` as rehypothecated collateral. `accrue-collateral-asset` calls `accrue-and-cache sBTC`, which cache-HITs the value from step 1 (pre-socialization `lindex`), overvaluing B's `zsBTC` collateral relative to its true post-socialization backing. [3](#0-2) 
4. B's health check passes against the inflated collateral valuation, allowing a borrow that would fail (or should trigger liquidation) against the real, socialized `lindex` — an outcome unreachable without step 2's action by a separate, unprivileged actor.

Note: full verification of `vault-accrue`'s exact tuple shape and confirmation that no other code path proactively invalidates `index-cache` on `socialize-debt` calls was based on the available indexed snippets for `v0-vault-sbtc.clar`/`v0-4-market.clar`; a background agent with full repository access should confirm this by tracing all callers of `socialize-debt` and all writers to `index-cache` to rule out an invalidation path not surfaced in this search.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L211-223)
```text
  (if (is-eq aid USDC) (contract-call? .v0-vault-usdc system-repay amount)
  (if (is-eq aid USDH) (contract-call? .v0-vault-usdh system-repay amount)
  (if (is-eq aid stSTXbtc) (contract-call? .v0-vault-ststxbtc system-repay amount)
  ERR-UNKNOWN-VAULT)))))))

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

**File:** mainnet/contracts/market/v0-4-market.clar (L270-293)
```text
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
                        ;; will cause ERR-UNKNOWN-VAULT with any value over 64
                        u100))))))))
          (begin
            (unwrap-panic (accrue-and-cache vault-id))
            acc))
        ;; Non-ztoken: skip accrual (no liquidity index needed)
        acc)))
```

**File:** docs/market.md (L627-634)
```markdown
### Cache Invalidation

Cache is **automatically invalidated** each block:
- Cache key includes `stacks-block-time` (block timestamp)
- New block → new timestamp → cache miss → fresh accrual
- No manual invalidation needed
- Eliminates stale data risks

```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L959-964)
```text
    (asserts! (> scaled-amount u0) ERR-AMOUNT-ZERO)

    (var-set lindex new-lindex)
    (var-set principal-scaled (if (> scaled-principal scaled-amount) (- scaled-principal scaled-amount) u0))
    (var-set total-borrowed (if (> borrowed principal-reduction) (- borrowed principal-reduction) u0))
    (var-set assets (if (> current-assets principal-reduction) (- current-assets principal-reduction) u0))
```
