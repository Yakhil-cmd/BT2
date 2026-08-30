### Title
Unprivileged callers can inject Pyth price updates via `price-feeds` that overwrite a shared oracle cache used to evaluate other users' positions in the same block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar`'s hot-path functions (`collateral-add`, `collateral-remove`, `borrow`, `liquidate`) accept an optional `price-feeds` parameter that lets **any caller** push a Pyth price update on-chain via `write-feeds`/`write-feed` before their own operation executes [1](#0-0) . This write lands in the globally shared `pyth-storage-v4.prices` map and `market.clar`'s `last-update` map [2](#0-1) , both of which are consulted by `price-resolve` for **every** user's health/liquidation calculation in that same block, not just the injecting caller's own position [3](#0-2) . This is structurally the same bug class as the reported `ValidateVoteExtensions` issue: data supplied by one unprivileged party is trusted and folded into a shared aggregate/state that is then used to make decisions affecting other parties.

### Finding Description
The staleness/monotonicity checks only bound how old or how "backwards" an update can be relative to the current block time and the previously recorded timestamp - they do not bind the update to the caller's own position:

- `pyth-storage-v4.write-batch-entry` only requires the new `publish-time` to be more recent than the last stored one and within `stale-price-threshold` seconds of block time [4](#0-3) .
- `market.clar`'s own freshness check `oracle-timestamp-fresh` only requires `delta <= max-staleness` and `ts >= prev` [5](#0-4) .

Any Pyth-signed update whose `publish-time` falls inside this window is accepted, regardless of who submits it or for what purpose. Because `write-feeds` is invoked unconditionally for `collateral-add`, `collateral-remove`, `borrow`, and `liquidate` before the rest of the operation runs [6](#0-5) , a caller can select and push whichever validly-signed (but not necessarily "current") price snapshot within the staleness window best serves their own transaction. That write mutates the shared `prices`/`last-update`/`index-cache` state that market.clar reads for **all** positions evaluated afterwards in the same block - including third-party borrowers who are not part of the caller's transaction.

Concretely, in `liquidate`, a liquidator (attacker) targeting victim Bob can:
1. Hold or obtain a validly Pyth-signed price update for Bob's collateral asset that is less favorable than the true current market price, but still inside the staleness window.
2. Call `liquidate(bob, ..., price-feeds: some([that update]))`.
3. `write-feeds` pushes that price into the shared oracle state [7](#0-6) , and the very same call's `get-notional-evaluation`/health check then reads that freshly-written price via `price-resolve`/`resolve-pyth` to determine Bob's LTV [8](#0-7) .
4. If that manipulated-but-signed price pushes Bob's LTV over `ltv-liq-partial`, Bob is liquidated at a price he never actually crossed in real market terms, and the attacker collects the liquidation bonus.

Because the same written price also persists in the shared `pyth-storage-v4.prices` map (and market's `last-update`) for the rest of the block, any other market.clar caller (another liquidator, another borrower's health check, etc.) reading that asset in the same block also consumes the attacker-primed value until a fresher, more-recent update arrives. This is exactly the "shared cache primed by one caller and consumed by another" pattern.

### Impact Explanation
An unprivileged liquidator can weaponize the caller-injected `price-feeds` parameter to force an otherwise-healthy borrower into liquidation using a stale-but-signed price snapshot, seizing the borrower's collateral plus the liquidation penalty bonus. This is a direct theft of a victim's collateral (funds at rest), qualifying as **Critical - direct theft of user funds**. Even in the milder case, borrowers can similarly injected-price their own `collateral-add`/`borrow` calls to their advantage against the protocol's risk model, but the liquidation path is the clearest theft-of-victim-funds vector.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to possess or obtain a validly Pyth-signed price message whose `publish-time` sits within the `stale-price-threshold`/`max-staleness` window but that is less favorable to the victim than the live price (e.g., replaying an update from a brief price dip that has since recovered, or timing the attack right after real volatility before a corrective update lands on-chain). Pyth guardians sign price messages continuously, and messages remain "not stale" for the configured window (`CARDINALITY` ~120 seconds per the docs) [9](#0-8) , giving a realistic window for an attacker to grab and replay an unfavorable-but-valid signed update against a victim who was healthy under the live price.

### Recommendation
- Do not allow `price-feeds` injected during a `liquidate` call (or any operation) to be applied against a position other than the caller's own without additional constraints; at minimum, require that the injected update's `publish-time` be strictly newer than what is already stored (already partially done) AND reject updates whose price deviates unfavorably from the position holder unless the update timestamp is the most recent available from the oracle (i.e., disallow "replaying" an older-but-still-fresh unfavorable price when a newer, more favorable one already exists).
- Consider decoupling price-writes from the hot-path business logic entirely for the `liquidate` function, or require a cooldown/second read after the write to prevent the same transaction from writing and then immediately consuming a self-selected price for punitive use against a third party.
- Add a per-call sanity bound (e.g., max price deviation vs. previous cached/last price) before accepting an injected update inside sensitive operations like `liquidate`.

### Proof of Concept
1. Alice deposits sBTC and borrows USDC at a healthy LTV (e.g., 70%), using the live BTC price.
2. BTC price briefly dips and Pyth guardians sign an update reflecting the dip; before the dip recovers, keepers push the recovery price on-chain, but the dip-price Pyth message is still within `stale-price-threshold`/`max-staleness` and has not been superseded by a *newer* `publish-time` in `pyth-storage-v4` for that specific feed (an attacker can grab the signed dip message the moment it was published, off-chain, and hold it).
3. Attacker (Charlie) calls `liquidate(alice, sbtc-ft, usdc-ft, debt-amount, min-collateral-expected, none, some([dip-price-message]))`.
4. `write-feeds` writes the dip price into `pyth-storage-v4.prices` (accepted because its `publish-time` is more recent than the previously stored `prev-publish-time` for that feed and within staleness bounds) [4](#0-3) .
5. The same `liquidate` call immediately re-resolves BTC's price via `resolve-pyth`/`price-resolve`, reading the just-written dip price, computes Alice's LTV as unhealthy, passes the `ltv-liq-partial` check, and liquidates Alice's sBTC collateral at the dip price plus penalty [10](#0-9) .
6. Alice's collateral is seized even though, by the true live market price, her position was never actually unhealthy.

Note: I was unable to fully verify from the indexed files whether `pyth-governance-v3.check-execution-flow`/`check-storage-contract` impose any additional whitelist restricting which principals may call `verify-and-update-price-feeds`/`write` in the mainnet deployment (grep found matches in `pyth-governance-v3.clar` but its full body wasn't returned by the search). If that governance layer restricts `write` to a whitelisted relayer set rather than allowing arbitrary `tx-sender`/`contract-caller` values, the exploitability of this specific path would be reduced accordingly; confirming this would require reading `pyth-governance-v3.clar` directly (recommend a Devin session with full file access to verify).

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L112-120)
```text
;; -- Index cache (for accrual)
(define-map index-cache
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })

;; -- Oracle timestamp tracking
(define-map last-update
  { type: (buff 1), ident: (buff 32) }
  uint)
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

**File:** local-testing/contracts/pyth/contracts/pyth-storage-v4.clar (L84-102)
```text
	(let ((stale-price-threshold (contract-call? .pyth-governance-v3 get-stale-price-threshold))
			(latest-stacks-timestamp (unwrap! (get-stacks-block-info? time (- stacks-block-height u1)) ERR_STALE_PRICE))
			(publish-time (get publish-time entry)))
		;; Ensure that we have not processed a newer price
		(asserts! (is-price-update-more-recent (get price-identifier entry) publish-time) ERR_NEWER_PRICE_AVAILABLE)
		;; Ensure that price is not stale
		(asserts! (>= publish-time (+ (- latest-stacks-timestamp stale-price-threshold) STACKS_BLOCK_TIME)) ERR_STALE_PRICE)
		;; Update storage
		(map-set prices 
			(get price-identifier entry) 
			{
				price: (get price entry),
				conf: (get conf entry),
				expo: (get expo entry),
				ema-price: (get ema-price entry),
				ema-conf: (get ema-conf entry),
				publish-time: publish-time,
				prev-publish-time: (get prev-publish-time entry)
			})
```

**File:** local-testing/contracts/market/market.clar (L387-393)
```text
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))
```

**File:** docs/oracle.md (L220-228)
```markdown
**Step 4: Validate freshness**
```clarity
// Price must not be stale (using stacks-block-time)
→ timestamp = 123456
→ current block timestamp = 123500
→ delta = 44 seconds
→ CARDINALITY = 120 seconds
→ Check: 44 <= 120 ✓ FRESH
```
```
