### Title
Liquidator can omit or partially omit price feed updates to liquidate borrowers using stale oracle prices - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`liquidate()` accepts an optional `price-feeds` parameter and passes it to `write-feeds`, which is a no-op when `none` is supplied or simply skips assets the caller chooses not to include. [1](#0-0)  Because price resolution (`price-resolve`) only requires that the cached price be within `max-staleness` and monotonically non-decreasing, not that it be freshly updated by the caller, a liquidator can choose not to push a fresh update and instead liquidate a borrower using whichever stale (but still "fresh enough") on-chain price is most favorable to the liquidator. [2](#0-1) 

### Finding Description
`liquidate()` calls `(write-feeds price-feeds)` where `price-feeds` is fully attacker-controlled and optional (`(optional (list 3 (buff 8192)))`). [1](#0-0)  `write-feeds` simply folds over whatever feeds are supplied — or does nothing at all if `none` is passed. [3](#0-2) 

The subsequent price used for the liquidation math comes from `price-resolve`, which accepts any cached price satisfying only two conditions: it is positive, and its timestamp delta from `stacks-block-time` is `<= max-staleness` (per-asset) and `>= ` the previously recorded timestamp. [4](#0-3)  There is no requirement that the caller's transaction actually update the price to the latest available value — a stale price already sitting in `pyth-storage`/cache that still satisfies `max-staleness` is accepted.

This gives an unprivileged liquidator control over which (still-valid) historical price within the staleness window is used to value the borrower's collateral and debt in `process-debt-asset` and `process-collateral-asset`, both of which consume the resolved `price` field directly to determine how much collateral is seized and how much debt is repaid. [5](#0-4)  The victim here is the borrower being liquidated (a different, unprivileged principal): the liquidator's choice of when to submit versus withhold a price update directly determines how much of the borrower's collateral is seized for a given debt repayment, or whether the position is deemed liquidatable at all.

### Impact Explanation
If the true (fresh) collateral price is higher than the stale cached price still within `max-staleness`, the liquidator can withhold the update and seize collateral valued at the lower stale price while collateral is actually worth more — extracting excess value from the borrower beyond what a fair, up-to-date liquidation would allow. Conversely, if the fresh debt price is lower than a stale cached one, the liquidator can use the stale higher debt price to justify seizing more collateral for the same repaid debt amount. This is a form of temporary/permanent value extraction from a specific borrower's collateral — a theft of unclaimed value from one user by another unprivileged user — fitting the "temporary freezing of funds" / theft-adjacent impact class, since the borrower ends up losing more collateral (or having less debt cleared) than a correctly-priced liquidation would produce.

### Likelihood Explanation
Likelihood is low-to-moderate: it requires (a) a volatile asset whose price moves meaningfully within the `max-staleness` window, and (b) the attacker being a market participant who is also the one submitting the liquidation transaction and therefore controls whether to include a price update. Since `price-feeds` is entirely optional and no mechanism forces the caller to push the current price before computing liquidation amounts, exploiting this only requires monitoring price movement and choosing the right moment/feed set to submit.

### Recommendation
Do not allow liquidation math to rely on a caller-optional price update. Either (a) require `price-feeds` to be non-empty and cover every asset involved in the liquidation (collateral and debt) before allowing `liquidate()` to proceed, or (b) enforce a much tighter staleness bound specifically for liquidation-time price resolution (e.g., require the price timestamp to be within the current or immediately preceding Stacks block), so that a liquidator cannot cherry-pick a favorable historical price still inside the general `max-staleness` window.

### Proof of Concept
1. Asset X has `max-staleness` = 120s. Its true price has just fallen (e.g., a big market move), but the on-chain cached price from ~100 seconds ago is still "fresh" per `oracle-timestamp-fresh`.
2. Borrower's position becomes liquidatable under the stale-but-valid price via `current-ltv` computed against `total-collateral-usd`/`total-debt-usd` from `get-notional-evaluation`. [6](#0-5) 
3. Attacker calls `liquidate(borrower, collateral-ft, debt-ft, debt-amount, min-collateral-expected, none, none)` passing `price-feeds` as `none`, skipping `write-feeds` entirely. [7](#0-6) 
4. `process-collateral-asset`/`process-debt-asset` compute `coll-actual`/`debt-actual` using the stale cached `coll-price`/`debt-price` still satisfying `max-staleness`, producing a seizure amount more favorable to the liquidator than the true current price would allow. [5](#0-4) 
5. Borrower loses more collateral value (or has less debt repaid) than a liquidation performed with the true current price would have caused.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L146-152)
```text
;; Process optional list of price feed updates
;; If list is provided, folds over it and updates all feeds
;; If list is none, does nothing (allows for backward compatibility)
(define-private (write-feeds (feeds (optional (list 3 (buff 8192)))))
  (match feeds
    entries (fold write-feed entries (ok true))
    (ok true)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L373-417)
```text
(define-private (price-resolve
  (data { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint }))
  (let ((type (get type data))
        (ident (get ident data))
        (key { type: type, ident: ident })
        (resolution (try! (resolve-price-feed type ident)))
        (price (get value resolution))
        (callcode (get callcode data))
        (final-price (try! (resolve-callcode price callcode)))
        (last-update-time (oracle-last-update key))
        (timestamp (get timestamp resolution))
        (max-staleness (get max-staleness data)))

    ;; validate price and timestamp using max-staleness from oracle data
    (asserts! (and (oracle-price-legal final-price) (oracle-timestamp-fresh timestamp last-update-time max-staleness))
              ERR-ORACLE-INVARIANT)

    ;; update timestamp if newer
    (if (> timestamp last-update-time)
        (map-set last-update key timestamp)
        false)

    (ok final-price)))

(define-private (price-multi-resolve
  (data (list 64 { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint }))
  (aids (list 64 uint)))
  (let ((init { output: (list), valid: true, aids: aids, idx: u0 })
        (response (fold iter-price-multi data init)))
    (asserts! (get valid response) ERR-ORACLE-MULTI)
    (ok (get output response))))

(define-private (iter-price-multi
  (oracle-data { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint })
  (acc { output: (list 64 uint), valid: bool, aids: (list 64 uint), idx: uint }))
  (let ((valid (get valid acc))
        (skip? (asserts! valid acc))
        (asset-ids (get aids acc))
        (idx (get idx acc))
        ;; resolve price - will use cache for ztokens
        (price (unwrap! (price-resolve oracle-data) (merge acc { valid: false })))
        (next (unwrap-panic (as-max-len? (append (get output acc) price) u64))))
    { output: next,
      valid: true,
      aids: asset-ids,
```

**File:** mainnet/contracts/market/v0-4-market.clar (L783-829)
```text
    }))

;; Process collateral asset for liquidation
;; Handles both enabled and disabled collateral assets
;; Calculates expected collateral, caps at user balance
;; Returns: { coll-actual: uint, coll-expected: uint, coll-price: uint, coll-decimals: uint }
(define-private (process-collateral-asset
  (coll-aid uint)
  (debt-actual-usd uint)
  (liq-penalty uint)
  (user-coll-balance uint)
  (assets (list 64 {
    id: uint, addr: principal, decimals: uint,
    oracle: { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint },
    collateral: bool, debt: bool, price: uint
  }))
  (coll-asset {
    id: uint, addr: principal, decimals: uint,
    oracle: { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint },
    collateral: bool, debt: bool
  }))
  
  (let (;; Calculate expected collateral in USD (with penalty bonus for liquidator)
        (coll-usd-expected (calc-liq-collateral-repay debt-actual-usd liq-penalty))
        
        ;; Handle disabled collaterals by resolving price if not in enabled assets
        (coll-asset-info (match (find-asset coll-aid assets)
                           ;; Found in enabled list: use it (already has price)
                           found found
                           ;; Not found (disabled): resolve price on demand
                           (let ((oracle-data (get oracle coll-asset))
                                 (price (unwrap-panic (price-resolve oracle-data))))
                             (merge coll-asset { price: price }))))
        (coll-price (get price coll-asset-info))
        (coll-decimals (get decimals coll-asset-info))
        (coll-expected (mul-div-down coll-usd-expected (pow u10 coll-decimals) coll-price))
        
        ;; cap at available collateral (user may not have enough)
        (coll-actual (if (> coll-expected user-coll-balance)
                         user-coll-balance
                         coll-expected)))
    {
      coll-actual: coll-actual,
      coll-expected: coll-expected,
      coll-price: coll-price,
      coll-decimals: coll-decimals
    }))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1382-1391)
```text
(define-public (liquidate
                (borrower principal)
                (collateral-ft <ft-trait>)
                (debt-ft <ft-trait>)
                (debt-amount uint)
                (min-collateral-expected uint)
                (collateral-receiver (optional principal))
                (price-feeds (optional (list 3 (buff 8192)))))
  (let (
    (feeds-check (try! (write-feeds price-feeds)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1409-1435)
```text
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
    (same-block-check (asserts! (not (is-eq last-borrow-block stacks-block-height)) ERR-LIQUIDATION-BORROW-SAME-BLOCK))

    ;; health check (FAIL-FAST) 
    ;; Check position is liquidatable BEFORE calling calc-liq-factor
    (health-check  (asserts! (>= current-ltv ltv-liq-partial) ERR-HEALTHY))
```
