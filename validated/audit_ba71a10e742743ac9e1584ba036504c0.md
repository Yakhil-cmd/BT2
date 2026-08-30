### Title
Caller-selectable stale (but validly-signed) oracle push price is cached and consumed by unrelated users' health/liquidation evaluations - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`v0-4-market.clar` exposes an optional, caller-supplied `price-feeds` parameter on `collateral-add`, `collateral-remove`, `borrow`, and `liquidate` that, when present, is fed into `write-feeds` → `write-feed` → the Pyth oracle's `verify-and-update-price-feeds`, which writes the decoded price into the shared, asset-keyed `prices`/`timestamps` maps in `pyth-storage-v4.clar` and into the market's own shared `last-update` map. This mirrors the reported bug class: an externally-influenced, optional input (here, *which* validly-signed price snapshot to push, within the allowed staleness window) determines state that is not scoped to the caller but is global, keyed only by `{type, ident}` (asset), and is subsequently read by `price-resolve`/`price-multi-resolve` for *any other* account's borrow/collateral/health/liquidation evaluation in the same or later transactions, exactly like the "shared cache primed by one caller, consumed by another" analog.

### Finding Description
`price-resolve` ( [1](#0-0) ) only enforces two invariants on an incoming price update: `oracle-price-legal` (price > 0) and `oracle-timestamp-fresh`, which requires `delta = stacks-block-time - ts <= max-staleness` and `ts >= last-update`. It does **not** require the pushed price to be the *latest* price available from Pyth — only that it is not older than `max-staleness` seconds and not older than whatever was previously recorded on-chain.

Because there is no scheduled/keeper price push in this design, the "canonical" on-chain price for an asset at any moment is whatever price snapshot the *last transaction that included `price-feeds`* chose to submit. Any unprivileged caller invoking `collateral-add`, `collateral-remove`, `borrow`, or `liquidate` ( [2](#0-1) , `write-feeds` at [3](#0-2) ) can select, among the set of genuinely Pyth-signed snapshots still within `max-staleness`, whichever historical price is most favorable to their own position. Pyth's own storage layer only rejects updates that are *older than the previous stored update* or older than its own staleness threshold ( [4](#0-3) ) — it does not require monotonic "freshest available" pushes either.

Once written, this price is stored in the shared maps (`last-update` in the market, `prices`/`timestamps` in `pyth-storage-v4`) keyed only by `(type, ident)`/`price-identifier`, not by the submitting account. Every subsequent read via `price-resolve`, `price-multi-resolve`, and `get-assets` (used by `get-notional-evaluation`, health checks, and liquidation math, e.g. [5](#0-4) ) consumes this same cached value for *every other account's* position evaluation until a fresher push overwrites it. Notably, `liquidate-multi`/`call-liquidate` always passes `none` for `price-feeds` ( [6](#0-5) ), meaning batch liquidators rely entirely on whatever price is already cached — a price an unrelated party (a borrower defending their own position) may have just chosen and pushed moments earlier in the same block.

### Impact Explanation
An attacker who is near a liquidation threshold can push (via `collateral-add`/`borrow`/etc. with `price-feeds`) the most favorable *validly-signed* historical price still inside the `max-staleness` window for their debt/collateral asset, instead of the freshest one. This:
- Can defend the attacker's own position from liquidation (self-only impact, out of scope on its own), **and**
- Simultaneously poisons the shared oracle cache consumed by `liquidate`/`liquidate-multi` calls targeting *other, unrelated borrowers* in the same or following block, before a fresher price arrives. A stale price chosen to be favorable to the attacker's asset direction can incorrectly raise or lower the computed collateral/debt USD value used to evaluate a stranger's health (`is-healthy`, `calc-liquidation-params`), either blocking a legitimate liquidation of an actually-insolvent third party (temporary freezing of the protocol's ability to recover bad debt, exposing lenders to eventual `socialize-debt` losses) or enabling a liquidator to seize a third party's collateral based on a distorted, attacker-chosen price rather than the true market price.

This lands on **High/temporary freezing of funds** (delay/prevention of legitimate liquidation of a third party's insolvent debt, socialized to lenders) and potentially edges toward **Critical/protocol insolvency** if bad debt accumulates while liquidations are blocked by attacker-primed stale prices.

### Likelihood Explanation
Requires the attacker to have a position near the liquidation boundary and to time a transaction with a favorably-old-but-still-valid Pyth signed update within the `max-staleness` window (commonly tens to ~120 seconds per the design docs) — achievable by monitoring recent Pyth price history and crafting/replaying a valid VAA from within that window. It also requires overlapping activity (another liquidation) in the same staleness window, which is opportunistic but realistic in volatile markets where multiple positions cross their thresholds together.

### Recommendation
- Require `price-feeds` submissions to reflect the most recent available Pyth publish time (e.g., reject updates whose `publish-time` lags the wormhole/Pyth guardian-attested "latest" by more than a small tolerance), rather than only checking monotonicity against the last locally stored value.
- Consider narrowing the acceptable staleness window used for price *pushes* (as opposed to strict read-side staleness), or require a keeper/permissionless-but-penalized "freshest price" push prior to any liquidation-affecting transaction.
- For `liquidate`/`liquidate-multi`, resolve/require a fresh price push scoped to the liquidation call itself rather than trusting whatever is already cached from an unrelated caller's prior transaction in the block.

### Proof of Concept
1. Attacker (Borrower B) holds a position close to the liquidation threshold on asset X.
2. Attacker observes recent valid Pyth VAAs for asset X and selects the oldest one still within `max-staleness` that yields the most favorable price for their position (e.g., higher price for their collateral, lower for their debt).
3. Attacker calls `collateral-add` (or any hot-path function accepting `price-feeds`) supplying that VAA as `price-feeds`; `write-feeds`→`write-feed` pushes it through `verify-and-update-price-feeds`, updating the shared `last-update`/`prices` map for asset X ( [7](#0-6) ).
4. Because `oracle-timestamp-fresh` only checks `ts >= last-update` and `delta <= max-staleness` ( [8](#0-7) ), this stale-but-valid price is accepted and becomes canonical for asset X.
5. Later in the same block, a liquidator calls `liquidate-multi` targeting unrelated Borrower V, which passes `none` for `price-feeds` ( [6](#0-5) ) and thus evaluates V's health using the attacker's previously-pushed stale price for asset X, producing an incorrect liquidation outcome for V (blocked liquidation of an actually-insolvent V, or a distorted seize amount).

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L128-152)
```text
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

**File:** mainnet/contracts/market/v0-4-market.clar (L691-756)
```text
(define-private (is-liquidation-paused (asset-id uint))
  (let ((manual-pause (var-get pause-liquidation))
        (global-grace-end (default-to u0 (map-get? liquidation-grace-periods GLOBAL-LIQUIDATION-GRACE-ID)))
        (asset-grace-end (default-to u0 (map-get? liquidation-grace-periods asset-id)))
        (global-grace-active (< stacks-block-time global-grace-end))
        (asset-grace-active (< stacks-block-time asset-grace-end)))
    (or manual-pause global-grace-active asset-grace-active)))

;; -- Liquidation: math helpers ----------------------------------------------

;; Calculate liquidation factor: ((ltv-curr - ltv-liq-partial) * BPS) / (ltv-liq-full - ltv-liq-partial)
;; Capped at BPS (100%) to prevent over-liquidation
(define-private (calc-liq-factor (ltv-curr uint) (ltv-liq-partial uint) (ltv-liq-full uint))
  (min BPS (div-bps-down (- ltv-curr ltv-liq-partial) (- ltv-liq-full ltv-liq-partial))))

;; Apply curve exponent for graduated liquidation
;; liq-factor = liq-factor^alpha
(define-private (calc-liq-factor-exp (factor uint) (exp uint))
  (if (is-eq exp BPS) 
    factor
    (if (> exp BPS) 
        (/ (pow factor (/ exp BPS)) (pow BPS (- (/ exp BPS) u1)))
        (sqrti (* factor BPS))))) ;; assume factor^0.5

;; Scale penalty between min and max using liquidation factor
;; liq-penalty = liq-penalty-min + (liq-factor * (liq-penalty-max - liq-penalty-min) / BPS)
;; Capped at bound-max to handle cases where liq-factor > BPS
(define-private (calc-liq-factor-bound (liq-factor uint) (bound-min uint) (bound-max uint))
  (min bound-max (+ bound-min (mul-bps-down liq-factor (- bound-max bound-min)))))

;; Calculate debt to repay based on liquidation factor
;; debt-repay = liq-factor * debt / BPS
(define-private (calc-liq-debt-repay (debt uint) (liq-factor uint)) 
  (mul-bps-down liq-factor debt))

;; Calculate collateral to seize (includes liquidator bonus)
;; collateral-repay = debt-repay * (BPS + liq-penalty) / BPS
(define-private (calc-liq-collateral-repay (debt-repay uint) (liq-penalty uint)) 
  (mul-bps-down debt-repay (+ BPS liq-penalty)))

;; Calculate actual debt repayment when collateral is capped
;; debt-repay-real = (collateral-amount-usd * BPS) / (BPS + liq-penalty)
(define-private (calc-liq-debt-repay-real (collateral-amount-usd uint) (liq-penalty uint)) 
  (div-bps-down collateral-amount-usd (+ BPS liq-penalty)))

;; Graduated liquidation parameter calculation
;; Combines the 4-step liquidation factor calculation into a single helper
;; Returns: { liq-pct-scaled: uint, liq-penalty: uint, max-debt-usd: uint }
(define-private (calc-liquidation-params
  (current-ltv uint)
  (ltv-liq-partial uint)
  (ltv-liq-full uint)
  (liq-penalty-min uint)
  (liq-penalty-max uint)
  (curve-exponent uint)
  (total-debt-usd uint))
  
  (let ((liq-pct-linear (calc-liq-factor current-ltv ltv-liq-partial ltv-liq-full))
        (liq-pct-scaled (calc-liq-factor-exp liq-pct-linear curve-exponent))
        (liq-penalty (calc-liq-factor-bound liq-pct-scaled liq-penalty-min liq-penalty-max))
        (max-debt-usd (calc-liq-debt-repay total-debt-usd liq-pct-scaled)))
    {
      liq-pct-scaled: liq-pct-scaled,
      liq-penalty: liq-penalty,
      max-debt-usd: max-debt-usd
    }))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L907-918)
```text
(define-private (call-liquidate (position { borrower: principal,
                                            collateral-ft: <ft-trait>,
                                            debt-ft: <ft-trait>,
                                            debt-amount: uint,
                                            min-collateral-expected: uint }))
  (liquidate (get borrower position)
             (get collateral-ft position)
             (get debt-ft position)
             (get debt-amount position)
             (get min-collateral-expected position)
             none   ;; collateral-receiver defaults to liquidator
             none)) ;; price-feeds not supported in batch - update prices separately
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1043-1044)
```text
                    ;; Accrue positions (required for price resolution)
                    (u-debt (accrue-user-debts (get debt position)))
```

**File:** local-testing/contracts/pyth/contracts/pyth-storage-v4.clar (L74-90)
```text
(define-private (write-batch-entry (entry {
		price-identifier: (buff 32),
		price: int,
		conf: uint,
		expo: int,
		ema-price: int,
		ema-conf: uint,
		publish-time: uint,
		prev-publish-time: uint,
	}))
	(let ((stale-price-threshold (contract-call? .pyth-governance-v3 get-stale-price-threshold))
			(latest-stacks-timestamp (unwrap! (get-stacks-block-info? time (- stacks-block-height u1)) ERR_STALE_PRICE))
			(publish-time (get publish-time entry)))
		;; Ensure that we have not processed a newer price
		(asserts! (is-price-update-more-recent (get price-identifier entry) publish-time) ERR_NEWER_PRICE_AVAILABLE)
		;; Ensure that price is not stale
		(asserts! (>= publish-time (+ (- latest-stacks-timestamp stale-price-threshold) STACKS_BLOCK_TIME)) ERR_STALE_PRICE)
```
