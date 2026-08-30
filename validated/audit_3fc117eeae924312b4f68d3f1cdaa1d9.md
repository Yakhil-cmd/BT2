## Finding

### Title
Liquidation and health-check operations revert entirely if a single asset in the borrower's position bitmask has an unresolvable price - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`get-assets` resolves oracle prices for *every* asset referenced in a user's collateral/debt bitmask in one atomic batch via `price-multi-resolve`/`unwrap-panic`. If price resolution fails for **any single asset** in that mask (stale timestamp, illegal price, or a callcode/index-cache failure), the whole call panics and the entire transaction reverts — including `liquidate()`, `borrow()`, and `collateral-remove()` for assets in the position that are completely unaffected and perfectly healthy. This is the direct analog of the `BasicIssuanceModule` issue: a multi-component operation (redeem N tokens / evaluate N asset prices) is made all-or-nothing, so a single "bad" component (an unpredictable ERC20 there, an unresolvable oracle feed here) blocks the legitimate claims of everyone else tied to that batch.

### Finding Description
`get-assets` builds the list of all asset ids relevant to a user's mask and resolves their prices together: [1](#0-0) 

`price-multi-resolve` folds over every oracle entry and, if a single `price-resolve` call fails (stale price, zero/negative price, `ERR-ORACLE-CALLCODE`, etc.), returns `ERR-ORACLE-MULTI`; the caller in `get-assets` immediately does `unwrap-panic` on that response: [2](#0-1) 

The staleness/legality gate that can fail per-asset is: [3](#0-2) 

`get-assets(mask)` is used to price *all* assets in the mask before computing `get-notional-evaluation`, and this is exactly the path `liquidate()` relies on to compute `total-collateral-usd`/`total-debt-usd` for the health check that gates liquidation: [4](#0-3) 

The liquidator can only submit a bounded batch of price updates per call (`price-feeds (optional (list 3 (buff 8192)))`) for both single (`liquidate`) and batch (`liquidate-multi`) liquidation: [5](#0-4) [6](#0-5) 

So a borrower whose position mask spans more than 3 distinct oracle-backed assets (e.g., collateral in one egroup asset, debt in another, plus a small dust collateral/debt in a fourth, thinly-traded asset with a tight `max-staleness`) can end up with a mask where the liquidator physically cannot refresh every needed feed in one tx, and if even one asset's on-chain price is stale/unresolvable, `get-assets`/`get-notional-evaluation` panics for the *entire* position — not just for that one asset. The same `get-assets`/`get-notional-evaluation` pattern also gates `borrow`, `collateral-add` (capacity check) and `collateral-remove`, so ordinary users with a live, healthy position but one "poisoned" dust asset in their mask are blocked too — but the more consequential victim class is the *other* market participants: while the borrower's position cannot be evaluated, an actually-undercollateralized position cannot be liquidated, so the debt keeps accruing/worsening and cannot be written down, harming depositors of the debt vault(s) who are relying on liquidation to cap losses.

### Impact Explanation
This lands on the "temporary freezing of funds" (and, if the offending asset's feed permanently stops updating and the borrower never repays, effectively permanent) category: liquidators (unprivileged third parties) and — more importantly — the suppliers of the vault(s) backing the borrower's debt are harmed because the write-off/liquidation of a genuinely unhealthy position can be indefinitely blocked by a single unresolvable price in the borrower's own mask, a shared state (`get-assets`/oracle resolution over the whole mask) that one caller (the borrower who took on debt/collateral in a fragile-feed asset) primes and that another caller (the liquidator, and transitively the depositors) cannot work around due to the 3-feed cap on `price-feeds`.

### Likelihood Explanation
Requires a borrower to hold collateral/debt across more than 3 oracle-backed assets simultaneously, at least one of which has a tight `max-staleness` and low external update frequency (plausible for lower-liquidity assets), and for that borrower's LTV to then cross the liquidation threshold. This is a natural, non-privileged scenario (no DAO compromise, no flashloan trickery needed) reachable purely by a borrower's asset selection and normal price drift.

### Recommendation
Do not require all-or-nothing price resolution for the full mask in health/liquidation paths. Either: (a) allow `liquidate`/`borrow`/`collateral-remove` to evaluate using only the assets actually needed for the specific action (target collateral/debt pair) plus a fallback conservative valuation (e.g., treat unresolvable assets as zero-value collateral / max-value debt, whichever is safe) instead of panicking; or (b) raise/parametrize the `price-feeds` batch limit so it can cover all assets in a position's mask, and make `iter-price-multi`/`get-assets` return a partial/degraded result instead of aborting the whole evaluation when a subset of feeds are stale.

### Proof of Concept
1. Borrower deposits collateral in assets A and B (each with distinct oracle feeds, egroup allows this combination) and borrows against a third asset C, then also deposits a small dust amount of a fourth thinly-traded asset D as additional collateral, where D's oracle feed has a short `max-staleness` and is rarely refreshed by external keepers.
2. Time passes such that D's on-chain oracle price exceeds `max-staleness`, while A, B, C remain fresh.
3. Borrower's LTV crosses `ltv-liq-partial` due to price movement in A/B/C.
4. A liquidator calls `liquidate` with `price-feeds` containing fresh updates for A, B, C (using all 3 available slots) — `get-liquidation-position`/`get-assets` still includes D in the mask, `price-resolve` for D fails `oracle-timestamp-fresh`, `price-multi-resolve` returns `ERR-ORACLE-MULTI`, and `get-assets` at [7](#0-6)  panics via `unwrap-panic`, reverting the entire liquidation.
5. The borrower's undercollateralized position (in A/B/C) remains open and cannot be liquidated as long as D's feed stays stale, harming suppliers of vault C who cannot recover the bad debt.

### Citations

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

**File:** mainnet/contracts/market/v0-4-market.clar (L397-418)
```text
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1382-1389)
```text
(define-public (liquidate
                (borrower principal)
                (collateral-ft <ft-trait>)
                (debt-ft <ft-trait>)
                (debt-amount uint)
                (min-collateral-expected uint)
                (collateral-receiver (optional principal))
                (price-feeds (optional (list 3 (buff 8192)))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1409-1436)
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1593-1599)
```text
(define-public (liquidate-multi
                (positions (list 64 { borrower: principal,
                                      collateral-ft: <ft-trait>,
                                      debt-ft: <ft-trait>,
                                      debt-amount: uint,
                                      min-collateral-expected: uint })))
  (ok (map call-liquidate positions)))
```
