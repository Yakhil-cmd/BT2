### No vulnerability found for this question.

The premise doesn't match the code. In `liquidate`, `coll-price` is not fetched via `get-cached-indexes` — that function only supplies the borrow/liquidity `index`/`lindex` used for debt-scaling and zToken callcode resolution, e.g. in `resolve-ztoken` and in `scale-debt-for-liquidation`'s `borrow-index` lookup [1](#0-0) . The actual `coll-price` value used throughout `liquidate` (including in the `remaining-debt-to-repay` computation) is set once in `process-collateral-asset` via either the pre-priced `assets` list or a single `price-resolve` call, and that same value is reused consistently for `coll-info`, `final-amounts`, `remaining-debt-to-repay`, and `target-coll-full-usd` [2](#0-1) [3](#0-2) .

Price feeds are written exactly once at the top of the `let`, before any accrual or price resolution, via `write-feeds`/`price-resolve`, both of which run atomically within the single `liquidate` invocation [4](#0-3) [5](#0-4) . Clarity execution is single-threaded and non-reentrant, so there is no way for A to "manipulate the oracle price between accrue and process-collateral-asset" inside one transaction — every read of `coll-price` within that call sees the same freshly-resolved, staleness-checked value enforced by `oracle-timestamp-fresh`.

The `remaining-debt-to-repay == u0` full-sweep branch is a deliberate anti-dust mechanism: it only triggers when the leftover collateral's USD value (at the liquidation-penalty-max exchange rate) rounds down to less than one unit of the debt token, which bounds the "excess" seized to a negligible dust amount, not a mechanism an attacker can scale up to seize meaningful value disproportionate to debt repaid [6](#0-5) . Repeated liquidate calls are also bounded by the LTV-based health check (`ERR-HEALTHY`) and the graduated `max-debt-usd` cap, which shrink further liquidation eligibility after each call [7](#0-6) .

Since the described staleness gap doesn't exist in the code and the dust-sweep branch is a bounded, intentional design choice, there's no exploitable path here.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L343-347)
```text
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L789-828)
```text
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
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1390-1414)
```text
  (let (
    (feeds-check (try! (write-feeds price-feeds)))
    (liquidator contract-caller)
    (position (try! (get-liquidation-position borrower)))
    (pos-full (try! (get-full-position borrower)))
    (mask (get mask position))
    (group (try! (get-egroup mask)))

    (coll-address (contract-of collateral-ft))
    (debt-address (contract-of debt-ft))
    (coll-asset (try! (get-asset coll-address)))
    (debt-asset (try! (get-asset debt-address)))
    (coll-aid (get id coll-asset))
    (debt-aid (get id debt-asset))

    ;; accrue FIRST - populates cache for zToken price resolution
    (u-debt (accrue-user-debts (get debt pos-full)))
    (u-coll (accrue-user-collateral (get collateral pos-full)))

    ;; NOW safe to resolve prices (cache is populated)
    (assets (get-assets mask))
    (notional-valued-assets (get-notional-evaluation { position: position, assets: assets }))
    (total-collateral-usd (get collateral notional-valued-assets))
    (total-debt-usd (get debt notional-valued-assets))

```

**File:** mainnet/contracts/market/v0-4-market.clar (L1433-1445)
```text
    ;; health check (FAIL-FAST) 
    ;; Check position is liquidatable BEFORE calling calc-liq-factor
    (health-check  (asserts! (>= current-ltv ltv-liq-partial) ERR-HEALTHY))

    ;; liquidation parameters (graduated liquidation calculation)
    (liq-params (calc-liquidation-params 
                  current-ltv ltv-liq-partial ltv-liq-full
                  liq-penalty-min liq-penalty-max 
                  curve-exponent total-debt-usd))
    (liq-pct-scaled (get liq-pct-scaled liq-params))
    (liq-penalty (get liq-penalty liq-params))
    (max-debt-usd (get max-debt-usd liq-params))

```

**File:** mainnet/contracts/market/v0-4-market.clar (L1476-1486)
```text
    (coll-remaining (- user-coll-balance coll-final-raw))
    (remaining-debt-to-repay
      (if (> coll-remaining u0)
        (let ((rem-coll-usd (normalize (* coll-remaining coll-price) coll-decimals false))
              (rem-debt-usd (div-bps-down rem-coll-usd (+ BPS liq-penalty-max)))
              (rem-debt-tokens (mul-div-down rem-debt-usd (pow u10 debt-decimals) debt-price))
              (rem-borrow-index (get index (unwrap-panic (get-cached-indexes debt-aid))))
              (rem-scaled (mul-div-down rem-debt-tokens INDEX-PRECISION rem-borrow-index)))
          (mul-div-up rem-scaled rem-borrow-index INDEX-PRECISION))
        u1))
    (coll-final (if (is-eq remaining-debt-to-repay u0) user-coll-balance coll-final-raw)))
```
