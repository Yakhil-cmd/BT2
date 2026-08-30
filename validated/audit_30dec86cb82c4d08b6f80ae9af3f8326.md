Confirmed: `socialize-debt` in each vault contract writes down `lindex` (liquidity index) proportionally when bad debt is socialized [1](#0-0) , and this same `lindex` is what prices every zToken of that vault via `resolve-ztoken`, which multiplies price by the cached `lindex` [2](#0-1) . The market's `liquidate-multi` batches multiple independent borrower liquidations in one atomic transaction via a plain ordered `map` over attacker-supplied positions [3](#0-2) , and within `liquidate`, a triggered bad-debt socialization immediately overwrites the shared, block-scoped `index-cache` for that asset with the new post-writedown indexes [4](#0-3) , which is then read by all subsequent price/health calculations in the same transaction via `get-cached-indexes` [5](#0-4) .

### Title
Order-dependent liquidation batching lets a liquidator manufacture unhealthiness in an otherwise-healthy borrower via same-block bad-debt socialization - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
`liquidate-multi` executes a caller-ordered list of liquidations atomically [6](#0-5) . When an earlier position in the batch has its bad debt socialized (because it had no collateral left), the vault's `lindex` is written down [7](#0-6)  and the market's shared, per-block `index-cache` is refreshed with the new lower `lindex` for that asset [8](#0-7) . Any later position in the same batch (or, by extension, in the same block) that holds a zToken of that same vault as collateral has its zToken price computed from that same freshly-lowered cached `lindex` [2](#0-1) , reducing that second borrower's collateral valuation and current LTV within the very transaction the liquidator constructs.

### Finding Description
`resolve-ztoken` prices a zToken as `underlying_price * lindex / PRECISION`; `lindex` is read exclusively from the market's shared `index-cache` keyed only by `{timestamp, aid}` (not by borrower) [9](#0-8) [2](#0-1) . `socialize-debt-asset`, invoked from `liquidate` whenever a liquidated borrower ends up with no remaining collateral [10](#0-9) , calls the vault's `socialize-debt`, which permanently reduces `lindex` proportionally to the loss versus total vault assets [7](#0-6) , and then market.clar immediately overwrites the block-scoped cache entry for that asset with the new (lower) index [8](#0-7) . Because `liquidate-multi` runs positions through `map call-liquidate positions` in the exact order supplied by the caller (the liquidator) within one atomic transaction [3](#0-2) , a liquidator can order the batch so that: (1) a first, genuinely-liquidatable borrower with a large bad debt on vault V is liquidated first and its residual debt is fully socialized (dropping V's `lindex` in the shared cache), then (2) a second borrower whose position holds zToken(V) as collateral and who was healthy at the start of the block is evaluated with the now-devalued zToken(V) price, pushing their LTV over the liquidation threshold within the same transaction, letting the liquidator immediately liquidate and seize collateral from a position that was not liquidatable before the attacker's own transaction began.

### Impact Explanation
This is theft of collateral from a borrower (victim) who was healthy prior to the liquidator's transaction: the liquidator's own batched transaction manufactures the unhealthy state used to justify seizing that victim's collateral, extracting the seize penalty that would not otherwise be earned. This lands on Critical - direct theft of user funds at rest (the victim's collateral) caused by a bug (shared, unscoped block-level index cache combined with unordered/attacker-ordered batch liquidation) rather than by the victim's own risk-taking.

### Likelihood Explanation
Requires: (a) at least one borrower on a given vault with debt large enough relative to that vault's `total-assets` to move `lindex` meaingfully upon socialization, and (b) a second borrower holding that vault's zToken as collateral sitting close to (but under) the liquidation threshold. Both conditions are plausible in a real market with correlated collateral usage (many users holding the same popular zToken, e.g. zUSDC), and the liquidator fully controls transaction ordering via `liquidate-multi`, making this exploitable without any privileged access, purely by choosing which positions to bundle and in what order.

### Recommendation
Make health/price evaluation order-independent within a batch: snapshot all relevant vault indexes (including projected post-socialization `lindex`) once at the start of `liquidate-multi` and use that fixed snapshot for every position in the batch, or disallow using a within-transaction, same-block-updated `lindex` for any position's price resolution other than the one whose socialization produced it. Alternatively, require `liquidate-multi` to process each position against the pre-transaction state (e.g., forbid a batch item's health check from observing writes made by an earlier item in the same batch), removing the caller's ability to choose an order that manufactures liquidatable positions.

### Proof of Concept
1. Borrower A on vault V (e.g. USDC) has an undercollateralized position that, once liquidated, leaves zero collateral, triggering `socialize-debt-asset` and reducing V's `lindex` via `vault-socialize-debt` / `socialize-debt` [11](#0-10) [7](#0-6) .
2. Borrower B holds zUSDC as collateral with an LTV just below `ltv-liq-partial`, healthy at the start of the block.
3. Liquidator calls `liquidate-multi` with `positions = [liquidate(A, ...), liquidate(B, zUSDC-collateral, ...)]` [3](#0-2) .
4. Processing A first writes the new lower `lindex` for USDC into `index-cache` [8](#0-7) .
5. Processing B reads that same cache entry via `get-cached-indexes`/`resolve-ztoken`, valuing B's zUSDC collateral lower than at the start of the block, pushing B's current LTV at/above `ltv-liq-partial` and passing the `health-check` that would otherwise fail [12](#0-11) , allowing the liquidator to seize B's collateral in the same batch.

I was not able to directly execute or simulate this in the codebase (no test harness run), so the numerical feasibility (how much `lindex` must move to flip a borderline-healthy position) is asserted from the formulas but not empirically verified against live protocol parameters.

### Citations

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

**File:** local-testing/contracts/market/market.clar (L365-369)
```text
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L890-896)
```text
            ;; Socialize in vault - pass scaled directly to avoid rounding
            (unwrap! (vault-socialize-debt asset-id scaled-debt) failed-status)
            ;; Refresh cache with new indexes post-write-down (lindex decreased)
            (map-set index-cache
                     { timestamp: stacks-block-time, aid: asset-id }
                     (unwrap! (vault-accrue asset-id) failed-status))
            ;; Remove from obligation
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1433-1435)
```text
    ;; health check (FAIL-FAST) 
    ;; Check position is liquidatable BEFORE calling calc-liq-factor
    (health-check  (asserts! (>= current-ltv ltv-liq-partial) ERR-HEALTHY))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1526-1548)
```text
          (no-collateral-left (and
                                (is-eq coll-removed u0)
                                (or
                                  (is-eq (len (get collateral pos-full)) u1)
                                  (and
                                    (is-eq (len (get collateral pos-full)) (len (get collateral position)))
                                    (is-eq other-debt-repayable u0))))))

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
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1587-1599)
```text
;; Liquidates multiple positions atomically
;; Each position can have different: borrower, collateral asset, debt asset, and debt amount
;; Prevents front-running attacks that prevent bad debt socialization
;; Note: price-feeds not supported in batch - update prices separately or use individual liquidate()
;; Returns list of responses - one per position (ok/err)
;; Failed liquidations return error codes but don't revert entire batch
(define-public (liquidate-multi
                (positions (list 64 { borrower: principal,
                                      collateral-ft: <ft-trait>,
                                      debt-ft: <ft-trait>,
                                      debt-amount: uint,
                                      min-collateral-expected: uint })))
  (ok (map call-liquidate positions)))
```
