### Title
Stale per-block index cache primed by one user's transaction is consumed by a later user's transaction, causing wrong debt/collateral valuation - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`v0-4-market.clar` caches vault liquidity/borrow indexes in a persistent map keyed only by `{ timestamp: stacks-block-time, aid }` via `accrue-and-cache`. The first transaction in a block to touch an asset populates this cache; every subsequent, unrelated transaction from a different user that touches the same asset in the same block reads the cached value instead of re-accruing, even if the underlying vault's persisted state (and therefore the "true" index) changed in between due to the first user's own borrow/repay/socialize-debt call.

### Finding Description
`accrue-and-cache` is implemented as: [1](#0-0) 

```
(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache cache-key)))
    (match cached?
      cached-indexes (ok cached-indexes)
      (let ((indexes (try! (vault-accrue aid))))
        (map-set index-cache cache-key indexes)
        (ok indexes)))))
```

`index-cache` is a contract-level persistent map, not scoped to a single transaction, and its key contains only `stacks-block-time` and `aid` — not the caller, not a transaction nonce, and not any hash of the vault's current persisted state. As documented, the intent is purely a gas optimization: "Multiple price resolutions for the same vault within a single block use cached indexes" and "Cache is automatically invalidated each block" [2](#0-1) , and the same pattern/doc is repeated for the vault design [3](#0-2) .

This cache is read by `borrow`, `collateral-add`, `collateral-remove`, and `liquidate` to value debt/collateral for health checks: `borrow` explicitly calls `accrue-user-debts`/`accrue-user-collateral` (which internally call `accrue-and-cache`) before computing `notional-valued-assets`, and reuses `get-cached-indexes` later in the same function to compute `scaled-debt-added` [4](#0-3) . `liquidate` and `collateral-add` follow the identical pattern [5](#0-4) [6](#0-5) .

Sequence that produces a stale read across two unrelated users:
1. User A (attacker or ordinary user) is first in a block to touch asset `X` (e.g. calls `borrow` on `X`). Early in A's transaction, `accrue-and-cache` computes and persists `index-cache[{timestamp: T, aid: X}]` based on the vault's state *before* A's own borrow executes.
2. Later in A's own transaction, `vault-system-borrow`/`vault-accrue` mutates the vault's persisted `total-borrowed`/`index`/`lindex` for asset `X` (interest-rate model reacts to new utilization).
3. User B, in a separate transaction later in the *same block* (same `stacks-block-time` `T`), performs any operation touching asset `X` (`borrow`, `collateral-add`, `collateral-remove`, or `liquidate` involving `X` as collateral/debt). `accrue-and-cache` hits the cache and returns A's stale, pre-mutation index instead of the vault's now-updated index.
4. B's health check, debt valuation, or liquidation math for `X` is computed against a stale index that does not reflect the utilization/interest change A already caused in the same block, and B has no way to detect or avoid this — B did not write the shared cache, A did.

This is a write to shared state (the block-scoped `index-cache`) by one uninvolved principal (A) that is silently consumed by another uninvolved principal (B), analogous to the reported bug class ("shared index or cache primed by one caller and consumed by another"). Because the cache key omits any commitment to the vault state that produced it, correctness depends on an implicit assumption that no state-mutating call to the same asset happens earlier in the block — an assumption the code does not enforce.

### Impact Explanation
Depending on the direction of drift between the stale cached index and the vault's true post-mutation index:
- A borrower (B) could pass a health check with an under-collateralized or under-valued debt because the cached debt index is lower than the true index, allowing more nominal debt to be recorded as "healthy" than is actually safe.
- A liquidator (B) could have their expected repay/seize amounts computed with a stale index, causing over- or under-seizure of collateral relative to the actual outstanding debt, or a liquidation that should be possible/impossible being blocked/allowed incorrectly.
- Bad-debt socialization computed off of a stale scaled/index value could mis-charge suppliers of the vault (all lenders of that asset) — freezing/misallocating unclaimed yield across the pool.

This lands on temporary freezing of funds / incorrect solvency accounting for a shared pool asset, since it stems from a code bug (an unscoped shared cache) rather than legitimate shared-pool economics or normal interest accrual.

### Likelihood Explanation
The condition requires only that two independent users' transactions touch the same asset within the same block timestamp (`stacks-block-time` granularity, not block height) — a common occurrence on any active market, and easily engineered by an attacker who front-runs their own state-mutating call (e.g. a large borrow) immediately before a victim's transaction that references the same asset in the same block, seeding a favorably stale cache entry for themselves or a targeted victim.

### Recommendation
Scope the `index-cache` key to the calling transaction rather than the block timestamp alone (e.g. invalidate/refresh on any state-mutating vault call for that `aid` within the same transaction context, or key the cache using a value that changes whenever the vault's persisted index changes, such as a monotonically increasing vault-side version/nonce). Alternatively, force cache invalidation for `aid` immediately after any operation (`system-borrow`, `system-repay`, `socialize-debt`) that mutates the vault's index/lindex for that asset, so subsequent unrelated callers in the same block are guaranteed a fresh read.

### Proof of Concept
Conceptual (Clarity function-level) reproduction, since this is a cross-transaction/same-block interaction rather than a single-call PoC:
1. Block N, Tx 1 (User A): call `borrow` on asset `X` with an amount large enough to materially shift `X`'s utilization/interest index. Observe that `accrue-and-cache` caches `index-cache[{timestamp: T, aid: X}]` using the pre-borrow vault state, then `vault-system-borrow` mutates the vault's persisted index for `X` afterward in the same transaction.
2. Block N, Tx 2 (User B): call `liquidate` or `borrow` referencing asset `X` (as debt or as zToken collateral). Confirm via the emitted `print` events (`borrow-index`, `position-debt-usd`, etc.) that B's transaction used the same `index-cache` entry set in Tx 1 (pre-Tx-1-mutation value), not the vault's actual updated index/lindex after Tx 1 completed.
3. Compare the health/liquidation outcome computed with the stale index against what would have resulted from a fresh `vault-accrue aid` call performed at the start of Tx 2 — demonstrating the valuation discrepancy attributable solely to the shared, unscoped `index-cache` map.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1043-1076)
```text
                    ;; Accrue positions (required for price resolution)
                    (u-debt (accrue-user-debts (get debt position)))
                    (u-coll (accrue-user-collateral (get collateral position)))

                    ;; Get current egroup and notional values
                    (current-group (try! (get-egroup current-mask)))
                    (current-ltv (buff-to-uint-be (get LTV-BORROW current-group)))
                    (feeds-check (try! (write-feeds price-feeds)))
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
                          (added-collateral-value (try! (get-asset-value asset amount false)))
                          (future-ltv (buff-to-uint-be (get LTV-BORROW future-group)))
                          (future-coll-usd (+ current-coll-usd added-collateral-value))
                          (future-capacity (* future-coll-usd future-ltv)))
                      ;; CRITICAL CHECK: Future capacity must not decrease
                      (asserts! (>= future-capacity current-capacity) ERR-UNHEALTHY))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1238-1296)
```text
(define-public (borrow (ft <ft-trait>) (amount uint) (receiver (optional principal)) (price-feeds (optional (list 3 (buff 8192)))))
  (let ((address (contract-of ft))
        (asset (try! (get-asset address)))
        (asset-id (get id asset))
        (account contract-caller)
        (funds-receiver (match receiver recv recv contract-caller))
        (feeds-check (try! (write-feeds price-feeds)))
        
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

        ;; Calculate current health with current mask
        (current-group (try! (get-egroup mask)))
        (current-ltvb (buff-to-uint-be (get LTV-BORROW current-group)))

        ;; LTV
        (notional-valued-assets (get-notional-evaluation { position: position, assets: assets }))
        (collateral-value (get collateral notional-valued-assets))
        (debt-value (get debt notional-valued-assets)))

    ;; preconditions
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (get debt asset) ERR-BORROW-DISABLED)
    (asserts! (is-healthy collateral-value debt-value current-ltvb) ERR-UNHEALTHY)

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
          (borrow-index (get index (unwrap-panic (get-cached-indexes asset-id)))))
      (try! (contract-call? .v0-market-vault
                            debt-add-scaled
                            account
                            scaled-debt-added
                            asset-id))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1405-1420)
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

**File:** docs/vaults.md (L301-319)
```markdown
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
