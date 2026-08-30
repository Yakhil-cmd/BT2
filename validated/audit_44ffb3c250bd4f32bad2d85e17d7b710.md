## Title
Borrower-controlled decoy asset with a stale/unavailable oracle can DoS liquidation of the entire position - (File: mainnet/contracts/market/v0-4-market.clar)

## Summary
`liquidate` (and `borrow`, `collateral-add`, `collateral-remove`) compute a position's health by calling `get-assets`, which resolves the price of **every** asset in the borrower's collateral+debt mask via `price-multi-resolve`/`iter-price-multi`, and then `unwrap-panic`s the result. If the oracle price for *any one* of the assets the borrower holds fails Zest's own freshness/confidence check, the whole call aborts — even if the specific debt/collateral pair a liquidator is trying to act on has a perfectly fresh, healthy price. This mirrors the Y2K M-11 pattern where an external price-feed dependency going "down" (Arbitrum sequencer) blocked the one action (`triggerDepeg`) needed to protect one class of users, letting the position resolve unfairly in favor of the other side.

## Finding Description
`get-assets` builds the list of oracle prices for the borrower's full safe mask (all enabled collateral the account holds plus all their debt assets): [1](#0-0) 

`price-multi-resolve`/`iter-price-multi` propagate a single failure from `price-resolve` into `ERR-ORACLE-MULTI`, and `price-resolve` itself reverts (`ERR-ORACLE-INVARIANT`) whenever a feed is stale, has a legal-but-invalid price, or fails the confidence check: [2](#0-1) 

`liquidate` calls `get-assets` unconditionally as part of computing `total-collateral-usd`/`total-debt-usd` for the *whole* position, before the specific collateral/debt pair being liquidated is even isolated: [3](#0-2) 

Because `get-assets` requires **every** asset id in the borrower's mask to resolve successfully (not just the debt/collateral pair the liquidator wants to act on), a borrower can hold a small amount of any asset whose oracle later becomes stale or unavailable and thereby make their entire position permanently un-evaluable — and hence un-liquidatable — for as long as that one feed stays broken, regardless of how underwater their real debt/collateral pair is.

This is materially worse for DIA-oracled assets (e.g. USDH): the optional `price-feeds` parameter accepted by `liquidate`/`borrow`/`collateral-add`/`collateral-remove` can only push fresh Pyth VAAs via `write-feed`/`write-feeds`; there is no mechanism in `market.clar` to force-refresh a DIA feed: [4](#0-3) [5](#0-4) 

So if the DIA (or an unmaintained Pyth) feed for one of a borrower's held assets stops updating past `max-staleness`, no liquidator-supplied `price-feeds` payload can unblock `liquidate` for that borrower — the same "external dependency down, can't trigger the critical action" situation as the referenced Arbitrum sequencer/`triggerDepeg` bug. Even the batch path offers no relief since `liquidate-multi`/`call-liquidate` always passes `none` for `price-feeds`: [6](#0-5) 

## Impact Explanation
Attacker = a borrower who deposits a small, disposable amount of an asset with a low-liquidity/rarely-updated oracle (e.g. USDH/DIA, or a thin Pyth feed) alongside their real collateral/debt. Victim = the lenders (LPs) of the debt vault, whose ability to have the position liquidated is a shared safety mechanism protecting their deposited funds. While the decoy asset's oracle is stale/down:
- Without the attacker's decoy deposit: liquidators can act on the debt/collateral pair as soon as it crosses the liquidation threshold, capping losses to LPs via the normal liquidation penalty/bad-debt-socialization flow.
- With the attacker's decoy deposit + a stale feed for that asset: every call to `liquidate` panics at `get-assets`/`price-multi-resolve`, so the position keeps accruing debt and losing real collateral value with no liquidation possible, growing bad debt that eventually gets socialized onto the vault's LPs (`socialize-debt-asset`) at a worse point than if timely liquidation had occurred.

This is a temporary freezing of LP funds (the liquidation safety valve is disabled) that can convert into a larger loss/insolvency for the debt vault's depositors — an unprivileged borrower harming unprivileged lenders through a bug in the position-health evaluation logic of this code, not through ordinary shared-pool economics.

## Likelihood Explanation
Any account can add a tiny amount of any currently-enabled asset as collateral via `collateral-add`, so constructing the decoy position requires no privilege. The triggering condition (an oracle exceeding its configured `max-staleness`, or a DIA feed pausing/lagging) is realistic and has previously occurred with third-party oracle networks; the protocol's own per-asset `max-staleness` design (documented as tunable, e.g. 60s for volatile assets) makes it easy for even brief feed delays to trip `ERR-ORACLE-INVARIANT` for one asset and freeze liquidation for the whole account.

## Recommendation
Scope liquidation's price/health evaluation to only the assets strictly required for the specific liquidation call (the debt asset being repaid and the collateral asset being seized), falling back to a full-position re-evaluation only when appropriate, or allow `get-assets`/`get-notional-evaluation` to tolerate/report per-asset oracle failures without aborting the entire liquidation. Alternatively, exclude/haircut any asset that has exceeded `max-staleness` from the health computation (treat as zero value) rather than reverting the whole transaction, and add a way to refresh/override DIA feeds (or move affected assets to Pyth) so liquidators are never permanently blocked by a single stale feed.

## Proof of Concept
1. Borrower deposits `sBTC` as real collateral and borrows `USDC` up to a healthy LTV.
2. Borrower also deposits `u1` of `USDH` (DIA-oracled) as collateral, adding `USDH`'s asset id to their mask.
3. The DIA oracle feed for `USDH` stops publishing updates (external outage) and its timestamp exceeds `max-staleness`.
4. `sBTC` price crashes, making the sBTC/USDC pair genuinely liquidatable.
5. A liquidator calls `liquidate(borrower, sbtc-ft, usdc-ft, ...)`. Inside `liquidate`, `get-assets(mask)` (mainnet/contracts/market/v0-4-market.clar:482-492) resolves prices for the borrower's full mask, including `USDH`; `price-resolve` for `USDH` fails freshness (`ERR-ORACLE-INVARIANT`, lines 373-388), `price-multi-resolve` marks the batch invalid, and `get-assets`'s `unwrap-panic` aborts the whole transaction.
6. No amount of `price-feeds` supplied by the liquidator can fix this, since `write-feed`/`write-feeds` only refresh Pyth feeds (lines 126-152), not DIA.
7. The sBTC/USDC position remains un-liquidatable indefinitely while USDH's feed is stale, growing bad debt that is ultimately socialized onto the USDC vault's LPs.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L322-335)
```text
(define-private (call-dia (key (string-ascii 32)))
  (let ((res (unwrap! (contract-call? 'SP1G48FZ4Y7JY8G2Z0N51QTCYGBQ6F4J43J77BQC0.dia-oracle get-value key) ERR-ORACLE-DIA)))
    (ok res)))

(define-private (resolve-dia (ident (buff 32)))
  (let ((key (unwrap-panic (from-consensus-buff? (string-ascii 32) ident)))
        (res (try! (call-dia key))))
    ;; DIA returns timestamp in milliseconds, convert to seconds for staleness check
    (ok { value: (get value res), timestamp: (/ (get timestamp res) u1000) })))

(define-private (resolve-price-feed (type (buff 1)) (ident (buff 32)))
  (if (is-eq type TYPE-PYTH) (resolve-pyth ident)
  (if (is-eq type TYPE-DIA) (resolve-dia ident)
  ERR-ORACLE-TYPE)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L373-418)
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
      idx: (+ idx u1) }))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L482-492)
```text
(define-private (get-assets (mask-user uint))
  (let ((mask-enabled (get-enabled-bitmap))
        (safe-mask (user-safe-mask mask-user mask-enabled))
        (iter (mask-to-list-collateral safe-mask))
        (assets-list (get-status-multi iter))
        (oracles-list (map get-oracle assets-list))
        ;; Extract asset-ids for price resolution
        (asset-ids (map get-asset-id assets-list))
        ;; Use internal price resolution
        (prices-list (unwrap-panic (price-multi-resolve oracles-list asset-ids))))
    (map merge-price assets-list prices-list)))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1405-1436)
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
