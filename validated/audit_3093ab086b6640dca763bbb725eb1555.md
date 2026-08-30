### Title
No minimum borrow/loan size enables uneconomical dust positions whose bad debt is socialized onto lenders - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
`borrow` in `v0-4-market.clar` only enforces `(asserts! (> amount u0) ERR-AMOUNT-ZERO)` before the health check; there is no `MIN-LOAN-SIZE` / minimum-debt floor anywhere in the codebase. [1](#0-0)  This lets a borrower open arbitrarily small debt positions (e.g. `1n` units of USDC), confirmed by the test suite which shows a 1-unit borrow succeeding rather than being rejected. [2](#0-1) 

### Finding Description
The `liquidate` function pays liquidators a bonus computed purely as a percentage of the debt repaid (`calc-liq-collateral-repay`, `calc-liquidation-params`), with no fixed minimum reward. [3](#0-2)  When debt is dust-sized, the absolute liquidation bonus is smaller than the gas cost of calling `liquidate`, so no rational liquidator will act. Because `borrow` never enforces a minimum loan size, an attacker (or ordinary accrual of interest on many small positions) can create numerous underwater dust positions that sit unliquidated. `liquidate` explicitly handles the case where a position ends up with zero collateral left and still has debt (`no-collateral-left`), triggering `socialize-debt-asset` over the fold of the borrower's remaining debt list and emitting a `bad-debt-socialized` event. [4](#0-3)  This socialization path is the mechanism by which uncollected bad debt from tiny, economically-unliquidatable positions is spread across all lenders in the vault — the exact "shared pool socialized to all suppliers" harm called out as in-scope. Because there is no `MIN-LOAN-SIZE` gate on `borrow`, this loss-shifting can be triggered cheaply and repeatedly by any unprivileged borrower, at the expense of unprivileged lenders who did not choose to take on this risk.

### Impact Explanation
Unliquidated dust debt accrues interest until it becomes bad debt that is socialized to lenders via `socialize-debt-asset`/`bad-debt-socialized`. [5](#0-4)  This is a protocol-insolvency-class impact: lenders permanently lose deposited funds to cover debt that liquidators had no incentive to clean up, matching the Critical impact category (protocol insolvency / permanent freezing of funds for depositors).

### Likelihood Explanation
Likelihood is elevated by the complete absence of any `MIN-LOAN-SIZE`, `MIN-BORROW`, or dust-check constant in the codebase (confirmed via full-repo search), and by an explicit test (`edge-cases.test.ts`, "should reject borrow that results in dust debt") whose assertions show the tiny borrow actually succeeding — indicating the team intended a minimum but never implemented the enforcement. An attacker only needs enough collateral to open one wei-sized borrow per position and can repeat this cheaply across many accounts/positions, since the only borrow-time check is `> amount u0` and standard health checks, both trivially satisfiable with a dust amount.

### Recommendation
Add and enforce a per-asset `MIN-LOAN-SIZE` (or minimum resulting-debt-in-USD threshold) check in `borrow` so that resulting debt cannot fall below the size at which the liquidation bonus meaningfully exceeds expected gas costs, preventing dust positions that can never be economically liquidated from being created in the first place.

### Proof of Concept
1. Borrower deposits normal collateral (e.g. 1 sBTC) via `market.collateralAdd`.
2. Borrower calls `market.borrow(usdcToken, 1n, ...)` — succeeds because `borrow` only checks `amount > 0` and standard LTV health, with no minimum debt-size floor. [6](#0-5) 
3. Repeat across many small positions/accounts; let interest accrue until each position crosses `LTV-LIQ-PARTIAL`.
4. Because the liquidator's bonus (`calc-liq-collateral-repay`) on a dust debt amount is smaller than transaction gas cost, no liquidator calls `liquidate`.
5. As positions continue accruing debt with no collateral value left, any eventual liquidation (or borrower-triggered path) that empties collateral while debt remains routes through the `no-collateral-left` branch, invoking `socialize-debt-asset` over the borrower's remaining debt and emitting `bad-debt-socialized`, shifting the loss onto all lenders in the vault. [5](#0-4)

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L726-756)
```text
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1238-1272)
```text
(define-public (borrow (ft <ft-trait>) (amount uint) (receiver (optional principal)) (price-feeds (optional (list 3 (buff 8192)))))
  (let ((address (contract-of ft))
        (asset (try! (get-asset address)))
        (asset-id (get id asset))
        (account contract-caller)
        (funds-receiver (match receiver recv recv contract-caller))
        (feeds-check (try! (write-feeds price-feeds)))
        
        ;; Step 1: Get position WITHOUT resolving prices
        (position (try! (get-position account)))
        (mask (get mask position))
        
        ;; Step 2: Accrue user's positions (populates cache for ztokens)
        (u-debt (accrue-user-debts (get debt position)))
        (u-coll (accrue-user-collateral (get collateral position)))
        
        ;; Step 3: Accrue the asset being borrowed (needed for index access)
        (unused (accrue-and-cache asset-id))
        
        ;; Step 4: NOW safe to resolve prices (cache is populated)
        (assets (get-assets mask))

        ;; Calculate current health with current mask
        (current-group (try! (get-egroup mask)))
        (current-ltvb (buff-to-uint-be (get LTV-BORROW current-group)))

        ;; LTV
        (notional-valued-assets (get-notional-evaluation { position: position, assets: assets }))
        (collateral-value (get collateral notional-valued-assets))
        (debt-value (get debt notional-valued-assets)))

    ;; preconditions
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (get debt asset) ERR-BORROW-DISABLED)
    (asserts! (is-healthy collateral-value debt-value current-ltvb) ERR-UNHEALTHY)
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

**File:** local-testing/tests/security/edge-cases.test.ts (L212-223)
```typescript
    it('should reject borrow that results in dust debt', async () => {
      txOk(market.collateralAdd(sbtcToken.identifier, 100000000n, null), alice);

      // Try to borrow very small amount
      const result = txOk(
        market.borrow(usdcToken.identifier, 1n, null, null),
        alice
      );

      // Should succeed but with minimal debt
      expect(result).toBeDefined();
    });
```
