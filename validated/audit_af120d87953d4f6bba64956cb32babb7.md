### Title
Permissionless, arbitrarily-timed Pyth price updates within the staleness window let a caller select stale-but-valid prices that other users' positions get liquidated/evaluated against - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`collateral-add`, `collateral-remove`, `borrow`, and `liquidate` in `mainnet/contracts/market/v0-4-market.clar` accept an attacker-controlled, permissionless `price-feeds` parameter that is written into the *global* Pyth price map via `write-feeds`/`write-feed` before any health/liquidation check runs [1](#0-0) . The only validation performed on submitted price data is a staleness/monotonicity check, not a "must be the freshest available" check, so any caller can select, within the allowed staleness window, whichever valid signed Pyth snapshot from the last `max-staleness` seconds is most favorable to them — and that snapshot becomes the shared price all other users' positions are evaluated against until someone pushes a newer one.

### Finding Description
`oracle-timestamp-fresh` only enforces that the submitted timestamp is within `max-staleness` seconds of the current block time and is monotonically non-decreasing relative to the last stored timestamp for that feed — it does not require the *latest* available price: [2](#0-1) 

```
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time) u0 (- stacks-block-time ts))))
    (and (<= delta max-staleness) (>= ts prev))))
```

This check is invoked from `price-resolve`, which is the single gate used for every asset valuation in the market (`collateral-add`, `collateral-remove`, `borrow`, `liquidate`): [3](#0-2) 

Any unprivileged caller can supply a `price-feeds` buffer to `write-feeds`, which forwards it to the Pyth storage contract's `verify-and-update-price-feeds`, writing directly into the shared, global `prices`/`timestamps` maps consumed by *all* market participants, not a caller-scoped value: [4](#0-3) 

Because Pyth's Hermes service and its historical VAAs remain cryptographically valid indefinitely (only the on-chain contract's staleness/monotonicity gate limits usability), an attacker can hold on to (or fetch) a genuinely signed but *older* price snapshot from within the `max-staleness` window (per-asset, configurable up to e.g. 300 seconds for "stable" assets per the design docs) [5](#0-4)  and submit it deliberately, choosing the specific snapshot that best serves their goal instead of the true current market price. Since this update is written to the shared oracle state before `liquidate`'s health check runs, and persists for use by every subsequent transaction against that feed until overwritten by a newer valid one, this is the exact bug class from the report — off-chain–signed data (Pyth VAAs, signed off-chain by Pythnet guardians) being processed on-chain out of sync with the true, current market condition — mapped onto Zest's shared, global oracle cache. The confidence-interval check (`check-confidence`) only bounds the *width* of the confidence interval relative to price magnitude; it does nothing to prevent selection of an old-but-tight-confidence snapshot that is stale relative to real-time market movement. [6](#0-5) 

Concrete attacker/victim path: A liquidator (attacker, unprivileged) calls `liquidate(borrower, ..., price-feeds: some(<stale-but-valid-VAA-showing-lower-collateral-price>))`. `write-feeds` pushes this stale price into the shared map, `price-resolve` accepts it (fresh enough, and `ts >= prev`), and the borrower's (victim's) currently-healthy position is revalued using this artificially depressed price, making `current-ltv >= ltv-liq-partial` true even though the position is solvent at the true current price: [7](#0-6) 
The liquidator then seizes the victim's collateral plus a liquidation penalty, even though the position was healthy under the actual current market price.

### Impact Explanation
The victim borrower's collateral is seized, and a liquidation penalty is charged, despite the position being solvent at the true, current market price — this is a direct theft of user funds at rest (the seized collateral) caused entirely by another unprivileged principal's (the liquidator's) choice of which valid-but-stale price snapshot to submit. This lands in the Critical impact class ("direct theft of user funds at rest ... or protocol insolvency"). The inverse direction (a borrower pushing a stale favorable price to delay their own liquidation while truly underwater) additionally exposes the protocol/other suppliers to bad debt via `socialize-debt-asset`, a socialization borne by all suppliers. [8](#0-7) 

### Likelihood Explanation
Exploitation requires only: (1) obtaining a genuinely Pythnet-signed but not-most-recent VAA within the configured `max-staleness` window (achievable by simply caching Hermes responses over the staleness window, e.g. up to 300 seconds for some assets), and (2) submitting it as the `price-feeds` argument to a permissionless, public function (`liquidate`) with no additional authorization. No governance, oracle, or key compromise is required. Likelihood increases during periods of high price volatility, where a price snapshot from even 30-60 seconds prior can materially misstate a position's health.

### Recommendation
- Require submitted price updates to strictly increase the on-chain `last-update` timestamp by a bounded, small amount relative to `stacks-block-time` for hot-path liquidation/health checks, or require that liquidation-critical price resolution always call `read-price-with-staleness-check`/re-verify against the most recent Hermes price rather than accepting any monotonically-newer-than-previous but still stale snapshot.
- Consider tightening `max-staleness` specifically for the liquidation code path (independent from collateral-add/borrow), since liquidation directly transfers value between two unprivileged parties.
- Add a check comparing the submitted price against a secondary/EMA reference (Pyth's `ema-price` is already available in the storage entry) and reject updates that deviate materially from the EMA, mitigating the selection of favorable-but-stale snapshots.
- Consider disallowing user-supplied `price-feeds` entirely inside `liquidate` (require prices to already be fresh from prior update transactions), removing the liquidator's ability to choose the exact snapshot used to justify their own liquidation.

### Proof of Concept
1. Borrower B deposits collateral and borrows against it; position is healthy at the true current market price P_now.
2. Market experiences a temporary price dip to P_low at time T-90s (within `max-staleness`, e.g. 120-300s per asset), then recovers to P_now by the time of the attack (T).
3. Attacker (liquidator L, unprivileged) fetches/caches the signed Pyth VAA for timestamp T-90s showing P_low.
4. L calls `liquidate(borrower=B, ..., price-feeds=some([VAA_at_T-90s]))`.
5. `write-feeds` → `write-feed` → Pyth's `verify-and-update-price-feeds` accepts the VAA (valid signature, `ts >= prev`, `delta <= max-staleness`) and stores P_low as the current price.
6. `price-resolve` in `liquidate` uses P_low, computing `current-ltv >= ltv-liq-partial`, even though B's position is solvent at P_now.
7. Liquidation proceeds; L receives B's collateral plus penalty, even though B's position was never actually undercollateralized at the real current price.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L126-152)
```text
;; -- Price feed update helpers ----------------------------------------------

;; Write a single Pyth price feed update using fold accumulator pattern
(define-private (write-feed (feed (buff 8192)) (status (response bool uint)))
  (match status
    success-status
      (match (contract-call? 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-oracle-v4 verify-and-update-price-feeds
          feed
          {
            pyth-storage-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-storage-v4,
            pyth-decoder-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-pnau-decoder-v3,
            wormhole-core-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.wormhole-core-v4,
          }
        )
        update-success (ok true)
        update-failed ERR-PRICE-FEED-UPDATE-FAILED)
    error-status status
  )
)

;; Process optional list of price feed updates
;; If list is provided, folds over it and updates all feeds
;; If list is none, does nothing (allows for backward compatibility)
(define-private (write-feeds (feeds (optional (list 3 (buff 8192)))))
  (match feeds
    entries (fold write-feed entries (ok true))
    (ok true)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L305-320)
```text
(define-private (check-confidence (price int) (confidence uint))
  (ok (asserts! (<= confidence (/ (* (to-uint price) (var-get max-confidence-ratio)) BPS)) ERR-PRICE-CONFIDENCE-LOW)))

(define-private (call-pyth (ident (buff 32)))
  (let ((res (unwrap! (contract-call? 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-storage-v4 get-price ident) ERR-ORACLE-PYTH)))
    (ok res)))

(define-private (resolve-pyth (ident (buff 32)))
  (let ((response (try! (call-pyth ident)))
        (price (get price response))
        (expo (get expo response))
        (conf (get conf response))
        (final-price (normalize-pyth price expo))
        (timestamp (get publish-time response)))
    (try! (check-confidence price conf))
    (ok { value: final-price, timestamp: timestamp })))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L365-371)
```text
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L373-395)
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
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1382-1394)
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
    (liquidator contract-caller)
    (position (try! (get-liquidation-position borrower)))
    (pos-full (try! (get-full-position borrower)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1424-1435)
```text
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

**File:** docs/oracle.md (L271-277)
```markdown
**Per-Asset Configuration:**
- Each asset defines its own `max-staleness` during registration
- Volatile assets can have shorter staleness (e.g., 60 seconds)
- Stable assets can have longer staleness (e.g., 300 seconds)
- `max-staleness > 0` required during asset registration

**Purpose:** Prevents using stale price data that could enable exploits, with flexibility per asset type.
```

**File:** local-testing/contracts/market/market.clar (L901-925)
```text
(define-private (socialize-debt-asset
                (debt-entry { aid: uint, scaled: uint })
                (acc { borrower: principal, success: bool }))
  ;; Early return if previous socialization failed
  (if (not (get success acc))
      acc
      (let ((borrower (get borrower acc))
            (failed-status { borrower: borrower, success: false })
            (asset-id (get aid debt-entry))
            (scaled-debt (get scaled debt-entry)))

            ;; Socialize in vault - pass scaled directly to avoid rounding
            (unwrap! (vault-socialize-debt asset-id scaled-debt) failed-status)
            ;; Refresh cache with new indexes post-write-down (lindex decreased)
            (map-set index-cache
                     { timestamp: stacks-block-time, aid: asset-id }
                     (unwrap! (vault-accrue asset-id) failed-status))
            ;; Remove from obligation
            (unwrap! (contract-call? .market-vault
                                      debt-remove-scaled
                                      borrower
                                      scaled-debt
                                      asset-id) failed-status)
          acc)
        ))
```
