## Title
Self-liquidation lets an underwater borrower socialize their own bad debt onto suppliers instead of repaying it - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`liquidate` in `mainnet/contracts/market/v0-4-market.clar` has no check preventing `borrower == contract-caller`. Combined with the bad-debt-socialization path that fires when a liquidated position runs out of collateral, an underwater borrower can liquidate themselves, recapture their own remaining collateral, and have the unpaid remainder of their debt written off across all suppliers of that vault instead of ever repaying it.

### Finding Description
`liquidate` only enforces `(asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)` and a same-block borrow check; it never asserts `liquidator != borrower`: [1](#0-0) [2](#0-1) 

`collateral-receiver` defaults to `liquidator` when unspecified, so a self-liquidating borrower simply receives their own collateral back: [3](#0-2) 

When the liquidated collateral asset is exhausted (`coll-removed` is `u0` and it was the borrower's only/last collateral, or all collateral has already been consumed), the function treats the position as having `no-collateral-left` and forgives whatever debt remains by calling `socialize-debt-asset` → `vault-socialize-debt` → the vault's `socialize-debt`, which writes down `lindex` (the supplier index) proportionally to the loss: [4](#0-3) [5](#0-4) [6](#0-5) 

The liquidation math caps the debt repaid by the borrower's actual collateral value (`process-collateral-asset`, `calc-final-liquidation-amounts`), so the amount they must pay through this path is only what their remaining collateral is worth (minus the liquidation penalty), not their full outstanding debt: [7](#0-6) [8](#0-7) 

The `socialize-debt` write-down reduces `lindex` for every zToken holder in that vault: [9](#0-8) 

### Impact Explanation
Victim: all suppliers (zToken depositors) of the debt-asset vault. Attacker: any borrower whose position is at or above `ltv-liq-partial`.

Without the attacker's transaction, an underwater borrower using `repay` must pay back the full outstanding debt (or partially repay, leaving the shortfall as their own liability, still tracked as debt owed by them) — no principal is destroyed and no supplier absorbs any loss.

With the attacker's transaction, the borrower (as liquidator) pays only the discounted, collateral-capped amount (`debt-to-repay`, bounded by `coll-final`/liquidation penalty math), reclaims their own residual collateral via `collateral-receiver = liquidator`, and the balance of the debt is erased via `vault-socialize-debt`, which lowers `lindex` and therefore every supplier's redeemable balance in that vault. This is a real transfer of value from suppliers to the borrower: unclaimed yield/principal held by suppliers is permanently reduced to cover a loss the borrower engineered rather than one caused by an uncontrollable market event. This lands in the "temporary/permanent freezing or loss of supplier funds via socialization" impact class (High), matching the imported report's High severity rating.

### Likelihood Explanation
Likelihood is Low-to-Medium: it requires the borrower's own position to already be undercollateralized enough to hit the `no-collateral-left` branch (analogous to the report's scenario where collateral value < required liquidation reward). This can occur naturally after a price drop, but a sophisticated borrower can also engineer it (e.g., borrow near max LTV, then let/force a small price move, or deliberately structure a single-collateral position) and then immediately self-liquidate before an honest third-party liquidator/keeper does, since `liquidate` is permissionless and has no cooldown preventing the borrower itself from calling it.

### Recommendation
Add an explicit check in `liquidate` (and the `liquidate-multi`/`call-liquidate` path) that `borrower != contract-caller` (and, if delegated calling is possible, that the effective borrower position owner is not the caller), or restrict debts that would trigger bad-debt socialization (`no-collateral-left` branch) to liquidations performed by allow-listed/privileged liquidators only, per the original report's recommendation.

### Proof of Concept
1. Attacker deposits a small amount of a single collateral type and borrows close to `ltv-liq-partial`/`ltv-liq-full`.
2. Price of collateral drops (or attacker structures a single-collateral position) such that `current-ltv >= ltv-liq-partial` and the collateral value is insufficient to cover full debt + liquidation penalty (the report's "100 vs 110" scenario).
3. Attacker calls `market.liquidate(borrower=self, collateral-ft, debt-ft, debt-amount=<large>, min-collateral-expected=0, collateral-receiver=none, price-feeds=none)` as `contract-caller`.
4. `debt-to-repay`/`coll-final` are capped by the attacker's remaining collateral value (`process-collateral-asset`/`calc-final-liquidation-amounts`/`scale-debt-for-liquidation`), so attacker repays only that capped amount and reclaims the residual collateral as `actual-receiver` (defaults to `liquidator`, i.e., attacker).
5. Since `coll-removed` ends up `u0` for a single/last collateral asset, `no-collateral-left` evaluates true, and `socialize-debt-asset` → `vault-socialize-debt` → `socialize-debt` writes off the remaining scaled debt, decreasing `lindex` for that vault's suppliers.
6. Net effect: attacker exits with far less loss than a full `repay` would have cost them; suppliers of the debt vault absorb the shortfall via the reduced `lindex`.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L808-853)
```text
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

;; Calculate final liquidation amounts with proportional adjustments
;; If collateral was capped, recalculates debt proportionally
;; Returns: { debt-final-usd: uint, debt-final: uint }
(define-private (calc-final-liquidation-amounts
  (debt-actual-usd uint)
  (coll-actual uint)
  (coll-expected uint)
  (coll-price uint)
  (coll-decimals uint)
  (debt-price uint)
  (debt-decimals uint)
  (liq-penalty uint))
  
  (let ((coll-actual-usd (normalize (* coll-actual coll-price) coll-decimals false))
        ;; If collateral was capped, recalculate debt proportionally
        (debt-final-usd (if (< coll-actual coll-expected)
                           (calc-liq-debt-repay-real coll-actual-usd liq-penalty)
                           debt-actual-usd))
        (debt-final (mul-div-down debt-final-usd (pow u10 debt-decimals) debt-price)))
    {
      debt-final-usd: debt-final-usd,
      debt-final: debt-final
    }))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L856-877)
```text
;; Converts to scaled units, caps at current debt, calculates final collateral
;; Returns: { scaled-to-remove: uint, debt-to-repay: uint, coll-final: uint }
(define-private (scale-debt-for-liquidation
  (debt-final uint)
  (coll-actual uint)
  (curr-scaled uint)
  (asset-id uint))
  (let (;; convert debt amount to scaled units for storage
        (borrow-index (get index (unwrap-panic (get-cached-indexes asset-id))))
        (scaled-debt (mul-div-down debt-final INDEX-PRECISION borrow-index))
        ;; cap at current debt (prevent over-repayment)
        (scaled-to-remove (if (> scaled-debt curr-scaled) curr-scaled scaled-debt))
        (debt-to-repay (mul-div-up scaled-to-remove borrow-index INDEX-PRECISION))
        ;; If debt was capped, scale collateral proportionally
        (coll-final (if (< scaled-to-remove scaled-debt)
                        (mul-div-down coll-actual scaled-to-remove scaled-debt)
                        coll-actual)))
    {
      scaled-to-remove: scaled-to-remove,
      debt-to-repay: debt-to-repay,
      coll-final: coll-final
    }))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1382-1396)
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
    (mask (get mask position))
    (group (try! (get-egroup mask)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1488-1493)
```text
    (asserts! (not (is-liquidation-paused debt-aid)) ERR-LIQUIDATION-PAUSED)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    (asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1504-1512)
```text
          ;; Collateral receiver defaults to liquidator if not specified
          (actual-receiver (match collateral-receiver recv recv liquidator))
          (coll-removed (try! (contract-call? .v0-market-vault
                              collateral-remove
                              borrower
                              coll-final
                              collateral-ft
                              coll-aid
                              actual-receiver)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1526-1560)
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

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L942-970)
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

    (print {
      action: "socialize-debt",
      caller: contract-caller,
      data: {
        scaled-amount: scaled-amount,
```
