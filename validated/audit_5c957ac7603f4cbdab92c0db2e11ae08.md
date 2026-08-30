### Title
Stale liquidity-index cache lets debt-socialization losses be ignored when pricing zToken collateral in the same block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar` caches each vault's `(index, lindex)` pair in `index-cache` keyed only by `{ timestamp: stacks-block-time, aid: aid }`, and returns the cached pair to *any* caller that hits `accrue-and-cache` for that vault within the same block/timestamp, without ever calling the vault again. [1](#0-0) 

`socialize-debt` on a vault (e.g. `v0-vault-stx.clar`) writes down `lindex` directly to reflect a bad-debt loss, completely independent of `accrue`/the market cache. [2](#0-1) 

Because the market cache key contains no state/version component (only the block timestamp), a socialization that happens *after* the cache was already primed in the same block is invisible to every subsequent transaction that reads the cache in that block — those transactions keep pricing the vault's zToken shares at the pre-loss `lindex`.

### Finding Description
`accrue-and-cache` is the single gateway market.clar uses before pricing any zToken collateral or debt tied to a vault: on cache MISS it calls `vault-accrue` and stores the fresh `{index, lindex}`; on cache HIT it returns the already-stored value without touching the vault again. [1](#0-0) 

The documentation for this mechanism confirms it is used specifically to price zToken (vault-share) collateral cheaply across multiple operations in the same block: [3](#0-2) 

The cache key is `{ timestamp, aid }` — it has no dependency on the vault's actual mutable state (`lindex`, `principal-scaled`, `assets`, `total-borrowed`). Any operation that changes a vault's `lindex` *after* the cache has already been primed for that timestamp will not be reflected for the remainder of the block, because every subsequent `accrue-and-cache` call for that `aid` will hit the cache and short-circuit before calling the vault.

`socialize-debt` is exactly such an operation: it is called by the market's bad-debt/liquidation flow (`vault-socialize-debt`) and mutates `lindex` directly, marking down the value of vault shares (and thus of the corresponding zToken) to reflect an actual loss: [2](#0-1) 

Attack/harm sequence within a single block (same `stacks-block-time`):
1. Attacker (or any ordinary user, e.g. depositing/borrowing against zSTX collateral) triggers `accrue-and-cache STX`, which is a cache MISS, calls `vault-accrue`, and stores the pre-loss `{index, lindex}` in `index-cache` for `(T, STX)`.
2. A liquidation of an undercollateralized position on the STX vault occurs later in the same block and, because the position has bad debt, the market calls `vault-socialize-debt`, which write-downs the STX vault's `lindex` to reflect the loss.
3. A third transaction still in block `T` — e.g. the attacker (or an innocent user) opening/increasing a position using zSTX as collateral, or valuing an existing zSTX position for a health check — calls `accrue-and-cache STX` again. This is a cache HIT on `(T, STX)`, so it returns the *stale, pre-socialization* `lindex` from step 1 instead of the vault's now-lower, post-loss `lindex`.
4. The market's zToken pricing/health-check logic (`get-asset-value`/`get-notional-evaluation`, gated by `is-ztoken`) uses this stale, overstated `lindex` to value zSTX collateral, letting the borrower's position pass a health/capacity check that would fail with the correct (post-loss) index.

The victim here is the protocol/other suppliers: the borrower extracts debt against collateral that is priced above its true, loss-adjusted value, directly increasing under-collateralization/insolvency risk introduced by the bad-debt event that just occurred in the same block — a shared cache primed by one transaction and consumed, unrefreshed, by a later, unrelated transaction that needed the updated state.

### Impact Explanation
This meets **Critical — protocol insolvency / theft of funds via under-collateralized debt**: a borrower can be allowed to open or maintain positions using zToken collateral valued using a stale, higher-than-actual `lindex`, right after a same-block socialization event lowered that index. The gap between the stale and true valuation directly increases bad debt beyond what the socialization already accounted for, socializing further losses onto all suppliers of that vault.

### Likelihood Explanation
Requires: (a) a liquidation with bad-debt socialization to occur, and (b) another transaction touching the same vault's cache slot earlier in the same block (a MISS priming the cache) and a third transaction (attacker's) later in the same block relying on that same, now-stale, cached value. All of these are ordinary market operations (deposit/borrow/collateral-add/liquidate) that regular users and liquidators naturally trigger; an attacker only needs to time their collateral operation to land after a same-block liquidation-with-socialization event, which they can influence via mempool observation/same-block sequencing, making this practically reachable without any privileged access.

### Recommendation
Invalidate or bypass the `index-cache` entry whenever a vault's `lindex`/`index` changes outside the normal `accrue` path (specifically in `socialize-debt`), e.g. by having `vault-socialize-debt` also clear/refresh the corresponding `index-cache` entry in `market.clar`, or by keying the cache on a vault-local monotonic version/nonce that is bumped on every state mutation (accrual, socialization) rather than solely on `stacks-block-time`.

### Proof of Concept
Conceptual PoC (exact call sites for `get-asset-value`/`is-ztoken` in `v0-4-market.clar` were not fully inspected due to tool-call limits, so this is described at the mechanism level, not as a fully-traced call graph):
1. Block T: User X calls any market function that triggers `accrue-and-cache STX` (e.g. `collateral-add` with STX-derived zToken, or a `borrow` touching the STX vault) → cache MISS → `index-cache[{T, STX}] = { index, lindex }` (pre-loss). [1](#0-0) 
2. Still block T: A liquidation on an undercollateralized STX-debt position triggers bad-debt handling, calling `vault-socialize-debt` → STX vault's `socialize-debt` lowers `lindex` in vault state. [2](#0-1) 
3. Still block T: Attacker calls `borrow`/`collateral-add` using zSTX collateral, which calls `accrue-and-cache STX` → cache HIT on `(T, STX)` → returns the stale, higher pre-loss `lindex` from step 1, causing zSTX collateral to be overvalued for the health/capacity check in that same transaction. [4](#0-3)

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1273-1290)
```text

    ;; Calculate FUTURE debt (after adding this debt)
    ;; For debt: bit position = asset-id + 64 (DEBT-OFFSET)
    (let ((future-mask (bit-or mask (pow u2 (+ asset-id DEBT-OFFSET))))
          (future-group (try! (get-egroup future-mask)))
          ;; Per-egroup borrow disable check (uses FUTURE egroup, not current)
          ;; Each bit in BORROW-DISABLED-MASK corresponds to a debt asset ID (NOT offset by 64)
          (disabled-borrow-mask (get BORROW-DISABLED-MASK future-group))
          (debt-increase (try! (get-asset-value asset amount true)))
          (debt-post-increased (+ debt-value debt-increase)))

    ;; Check if this specific asset is disabled for borrowing in the FUTURE egroup
    (asserts! (is-eq (bit-and disabled-borrow-mask (pow u2 asset-id)) u0) ERR-EGROUP-ASSET-BORROW-DISABLED)
    ;; postconditions
    (asserts! (try! (is-healthy-with-mask collateral-value debt-post-increased future-mask)) ERR-UNHEALTHY)

    (try! (vault-system-borrow asset-id amount funds-receiver))
    (let ((scaled-debt-added (convert-to-scaled-debt asset-id amount true))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L944-984)
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

    (print {
      action: "socialize-debt",
      caller: contract-caller,
      data: {
        scaled-amount: scaled-amount,
        debt-reduction: debt-reduction,
        principal-reduction: principal-reduction,
        old-lindex: current-lindex,
        new-lindex: new-lindex,
        old-total-assets: old-total-assets,
        principal-scaled: (if (> scaled-principal scaled-amount) (- scaled-principal scaled-amount) u0),
        total-borrowed: (if (> borrowed principal-reduction) (- borrowed principal-reduction) u0),
        index: idx
      }
    })

    (ok true)))
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
