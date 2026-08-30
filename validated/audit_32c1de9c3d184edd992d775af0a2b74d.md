## Title
Missing deviation/staleness check on the stSTX (LST) exchange rate lets a borrower mint over-valued collateral and push bad debt onto vault depositors - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar` prices the liquid-staked-STX asset (`stSTX`/`zstSTX`) by multiplying the STX/USD Pyth price by an external "STX-per-stSTX" exchange rate fetched from `block-info-nakamoto-ststx-ratio-v2`. Unlike the base Pyth/DIA feeds, this ratio carries no timestamp, no staleness bound, and no deviation/sanity check against any independent reference. This is exactly the bug class described in the Sherlock report: an LST exchange-rate oracle used for a non-pegged, appreciating asset with no on-chain deviation guard, allowing a delayed or manipulated ratio to be exploited before it updates.

### Finding Description
`resolve-ststx` applies the ratio unconditionally to the base STX price: [1](#0-0) 

The ratio itself comes straight from the external stacking-pool contract with no freshness/deviation validation: [2](#0-1) 

Contrast this with the base price path, `price-resolve`, which does validate `oracle-price-legal` and `oracle-timestamp-fresh` — but only for the Pyth/DIA feed value, not for the ratio applied on top of it by `resolve-callcode`/`resolve-ststx`: [3](#0-2) 

Because `stSTX`/`zstSTX` price = `STX-price × ratio`, and `ratio` is trusted at face value regardless of how stale or how far it has drifted from the real backing value of stSTX, a borrower can exploit any lag between the on-chain ratio and stSTX's true value (e.g., after a stacking-pool loss/slashing-like event, or simply a delayed ratio update) to post stSTX as collateral at an inflated USD value and borrow other vault assets (USDC, sBTC, USDH, etc.) against it in the same transaction, before the ratio is corrected.

If the position subsequently has no recoverable collateral, `liquidate` triggers bad-debt socialization, which writes down the *debt* vault's `lindex` — a value shared by every depositor of that vault, not just the attacker's counterparty: [4](#0-3) [5](#0-4) 

The actual loss is applied by `socialize-debt` in the underlying vault, which reduces `lindex` proportionally to the shortfall — this directly and permanently reduces the redeemable value for every LP holding that vault's shares: [6](#0-5) 

The attacker (borrower who over-borrows against an over-valued stSTX collateral) and the victims (all depositors/LPs of the debt-asset vault, e.g. `v0-vault-usdc`) are two distinct, unprivileged principals connected only through the shared vault `lindex` state — matching the "socialization charged to all suppliers" pattern.

### Impact Explanation
Without the attacker's transaction, the ratio would eventually self-correct (or be corrected off-chain) with no loss to the protocol. With the attacker's transaction, debt is originated against collateral that is not actually worth the value assigned to it; when that debt cannot be fully recovered through liquidation, the shortfall is socialized via `lindex` write-down onto all depositors of the borrowed asset's vault — a permanent, protocol-wide loss of principal for uninvolved suppliers. This is a form of protocol insolvency / permanent loss of user funds at rest, in the Critical impact category.

### Likelihood Explanation
This requires (a) the external `get-ststx-ratio-v3` value to lag or diverge from stSTX's real value — plausible given it's sourced from a single external stacking contract with no cross-check — and (b) the attacker to act (front-run/bundle) before any off-chain monitoring or DAO pause can react, exactly as described in the referenced report. There is no on-chain guard (deviation cap, confidence check, or staleness bound) analogous to `max-confidence-ratio`/`oracle-timestamp-fresh` that exists for the Pyth/DIA feeds themselves.

### Recommendation
Add an on-chain sanity check for the stSTX ratio analogous to the Pyth confidence check already present for base feeds: e.g., bound the ratio's per-call growth rate (AAVE's `maxRatio`/expected-growth approach) or cross-check it against a secondary reference before using it in `resolve-ststx`/`resolve-callcode`. Reject or clamp price resolution when the ratio deviates beyond the bound instead of trusting `call-ststx-ratio` unconditionally.

### Proof of Concept
1. External stacking-pool ratio lags a downward re-basing/loss event (ratio still reports the old, higher STX-per-stSTX value).
2. Attacker acquires stSTX cheaply on the open market, deposits it via `collateral-add`, and the market prices it using the stale, inflated `call-ststx-ratio` value via `resolve-ststx`/`resolve-callcode`.
3. Attacker borrows the maximum allowed debt (e.g. USDC) against this over-valued collateral in the same/adjacent transaction, then exits.
4. Once the ratio corrects, the position is undercollateralized; upon liquidation with no collateral left, `socialize-debt-asset` calls `vault-socialize-debt`, writing down `lindex` in the USDC vault, socializing the loss across all USDC vault depositors. [7](#0-6)

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L339-341)
```text
(define-private (resolve-ststx (p uint))
  (let ((ratio (unwrap! (call-ststx-ratio) ERR-ORACLE-CALLCODE)))
    (ok (mul-div-down p ratio STSTX-RATIO-DECIMALS))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L360-395)
```text
;; -- Oracle: price resolution -----------------------------------------------

(define-private (oracle-price-legal (p uint))
  (> p u0))

(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))

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

**File:** mainnet/contracts/market/v0-4-market.clar (L879-903)
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
            (unwrap! (contract-call? .v0-market-vault
                                      debt-remove-scaled
                                      borrower
                                      scaled-debt
                                      asset-id) failed-status)
          acc)
        ))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1014-1016)
```text
;; ststx ratio transformation
(define-public (call-ststx-ratio)
  (contract-call? 'SP4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7DVMDPBG.block-info-nakamoto-ststx-ratio-v2 get-ststx-ratio-v3))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1534-1560)
```text
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
                        ;; emit bad-debt-socialized event
                        (print {
                          action: "bad-debt-socialized",
                          caller: contract-caller,
                          data: {
                            borrower: borrower,
                            debt-list: fresh-debt-list
                          }
                        })
                        true)
                      false))
                  false)))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L944-966)
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
