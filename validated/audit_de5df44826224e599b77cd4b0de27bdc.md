## Analysis

Zest's `liquidate` function in `mainnet/contracts/market/v0-4-market.clar` reproduces the underlying bug class from the Morpho report: a **fixed, capped liquidation-penalty schedule combined with a single-oracle-update health check** lets a borrower harvest their own collateral at a bounded discount while the debt shortfall is socialized onto the lending-pool depositors — an unprivileged-borrower-harms-unprivileged-lenders pattern.

The graduated-liquidation curve (`calc-liq-factor`, `calc-liq-factor-bound`) is *capped* at `LTV-LIQ-FULL`/`LIQ-PENALTY-MAX`: once LTV crosses `LTV-LIQ-FULL` the liquidation percentage saturates at 100% and the penalty saturates at `LIQ-PENALTY-MAX` (e.g. 10%) no matter how far past the threshold the price has moved [1](#0-0) . When collateral value crashes well past that cap in a single oracle update, `process-collateral-asset`/`calc-final-liquidation-amounts` cap the seized collateral at the user's balance and recompute a smaller `debt-final`, leaving the unrepaid remainder to be written off via `socialize-debt-asset` → `vault-socialize-debt` [2](#0-1) .

Critically, `liquidate` contains **no check preventing the borrower from liquidating their own position** — the only anti-abuse guard is `last-borrow-block`, which only blocks borrowing and liquidating in the *same* block (aimed at flash-loan-style same-block attacks) [3](#0-2) . A borrower who opens a position in one block and self-liquidates in any *later* block after a large price move is unaffected by this guard, and `price-feeds` can even be supplied in-band to `liquidate` itself, letting the attacker push the crashing price update and immediately harvest it in the same transaction [4](#0-3) .

This is precisely the risk the project's own test `ATK-LG-05: Bad debt cannot be artificially created` explores, but that test only verifies that bad debt gets socialized when collateral is exhausted — it does not prevent the borrower from being the one to trigger and capture the liquidation itself [5](#0-4) .

### Title
Borrower can self-liquidate after a large single-block oracle price update to seize discounted collateral while socializing the shortfall as bad debt onto lenders - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
The `liquidate` function caps the liquidation penalty at `LIQ-PENALTY-MAX` and the liquidation percentage at 100% once LTV crosses `LTV-LIQ-FULL`, with no upper bound tied to how far past that threshold the position has moved. Combined with the absence of any check preventing a borrower from liquidating their own position, an attacker can borrow near the max LTV, wait for (or trigger via the in-band `price-feeds` parameter) a sufficiently large single oracle price update, and then liquidate themselves, seizing all remaining collateral at the fixed maximum discount while the unrecoverable debt is socialized to the lending-pool depositors of the debt asset via `socialize-debt-asset`.

### Finding Description
`calc-liquidation-params` computes `liq-pct-scaled` and `liq-penalty` from `current-ltv`, `ltv-liq-partial`, and `ltv-liq-full`, but both values saturate: `calc-liq-factor` is `min BPS ...` and `calc-liq-factor-bound` is `min bound-max ...` [1](#0-0) . This means that for any LTV at or beyond `LTV-LIQ-FULL`, the liquidator receives exactly `LIQ-PENALTY-MAX` bonus regardless of how deep the position is underwater.

When the collateral is insufficient to cover `debt * (1+LIQ-PENALTY-MAX)`, `process-collateral-asset` caps `coll-actual` at the user's balance, and `calc-final-liquidation-amounts` recomputes a smaller `debt-final-usd` proportional to the seized collateral [6](#0-5) . The liquidator (who can be the borrower) walks away with essentially all remaining collateral, minus only the (now smaller) amount they had to repay. The remaining scaled debt on the position is then written off via `socialize-debt-asset`, which calls `vault-socialize-debt` to write down the vault's `lindex` — proportionally reducing the redeemable value for every depositor of that debt asset [2](#0-1) , [7](#0-6) .

The only guard against abusive borrow-then-liquidate sequencing is the same-block check `(asserts! (not (is-eq last-borrow-block stacks-block-height)) ERR-LIQUIDATION-BORROW-SAME-BLOCK)` [3](#0-2) , which only prevents doing both actions atomically in one block; it does not check `liquidator != borrower`, and it does not stop a borrower from opening a position at max LTV well in advance and self-liquidating in the very next block once a legitimate but large price move occurs — an event that is a normal, expected occurrence for volatile collateral. `liquidate` also directly accepts an optional `price-feeds` parameter that lets any caller (including the attacker) atomically push the qualifying price update inside the same liquidation transaction [4](#0-3) .

### Impact Explanation
Victim: the depositors/lenders supplying the debt asset (e.g. USDC/USDH vault). Shared state: the vault's `lindex`/`total-borrowed` accounting, written down by `socialize-debt-asset`/`vault-socialize-debt`. Without the attacker's self-liquidation transaction, the position would either recover (price rebounds) or be liquidated by a neutral third-party liquidator who has no incentive to intentionally create bad debt for their own gain (a rational third party liquidates as much healthy collateral as covers debt+bonus, and only accepts a shortfall when truly forced to by exhausted collateral — the borrower, in contrast, deliberately engineers the shortfall to enrich themselves at lenders' expense, since they are recapturing collateral that would otherwise have gone to a legitimate liquidator or been distributed pro-rata). With the attacker's transaction, all remaining collateral flows back to the attacker (the borrower-turned-liquidator) at a bounded ~`LIQ-PENALTY-MAX` premium, and any excess debt beyond what collateral (minus that premium) can cover is stripped from the borrower's obligation and permanently absorbed by the vault's suppliers via the write-down of `lindex`. This is a permanent loss of principal for lenders — a direct theft of funds at rest, landing on the Critical impact class.

### Likelihood Explanation
The prerequisite — a single oracle update moving price enough to push a max-LTV position from healthy straight past `LTV-LIQ-FULL` — is the same "medium probability, high severity" event the original report describes: it occurs during genuine volatility spikes or de-peg-adjacent events for any listed collateral/debt pair, and Zest's own egroup configuration allows LTV bands (e.g. `LTV-BORROW`=80%, `LTV-LIQ-FULL`=90%) that can be crossed by a realistic single price tick for volatile assets like sBTC/stSTX. Because there is no restriction on the liquidator being the borrower, and no cooldown beyond one block between the qualifying borrow and the self-liquidation, execution requires no privileged access, no flashloan, and no third-party cooperation.

### Recommendation
Add an explicit check rejecting `liquidator == borrower` (or apply a stricter, non-bounded liquidation-penalty/haircut for self-liquidation), and/or scale the liquidation penalty/repayment requirement further as LTV exceeds `LTV-LIQ-FULL` (rather than fully saturating at `LIQ-PENALTY-MAX`) so that a borrower cannot profit from engineering or opportunistically exploiting a single large price move against their own position. Consider also requiring a minimum elapsed time/blocks since the position was last modified before allowing the same principal to be both the position owner and the liquidation beneficiary.

### Proof of Concept
1. Attacker deposits collateral (e.g. sBTC) and borrows the debt asset (e.g. USDC) up to `LTV-BORROW` (e.g. 80%) via `borrow` in block N.
2. In block N+1 (or later), a legitimate Pyth price update — pushed by anyone, or supplied by the attacker themselves in the `price-feeds` parameter of the `liquidate` call — moves the collateral price down enough that `current-ltv` computed in `liquidate` [8](#0-7)  lands well past `LTV-LIQ-FULL` (e.g. 99%).
3. Attacker (using the same or a colluding address as `liquidator`, since no `liquidator != borrower` check exists) calls `liquidate` on their own position with `debt-amount` set high. `same-block-check` passes because the borrow was in a prior block [9](#0-8) .
4. `calc-liquidation-params` returns `liq-pct-scaled = BPS` (100%) and `liq-penalty = LIQ-PENALTY-MAX` [10](#0-9) ; `process-collateral-asset`/`calc-final-liquidation-amounts` cap collateral seized at the attacker's full remaining balance and shrink `debt-final` accordingly [6](#0-5) .
5. `no-collateral-left` evaluates true (all collateral removed) and the residual scaled debt is written off through `socialize-debt-asset` → vault `socialize-debt`, permanently reducing the debt-asset vault's `lindex` and thus lenders' redeemable balances [11](#0-10) .
6. Net result: attacker recovers essentially all their collateral (minus the reduced `debt-final` they had to repay), and the difference between the pre-crash debt and the recovered `debt-final` is a permanent loss borne by all suppliers of that debt-asset vault.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L701-719)
```text
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
```

**File:** mainnet/contracts/market/v0-4-market.clar (L736-756)
```text
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

**File:** mainnet/contracts/market/v0-4-market.clar (L841-853)
```text
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1422-1426)
```text
    ;; LTV = (debt x 10,000) / collateral
    ;; handle edge case: If collateral = 0, return max LTV (BPS) or 0 if debt also 0
    (current-ltv   (if (is-eq total-collateral-usd u0)
                       (if (is-eq total-debt-usd u0) u0 BPS)
                       (mul-div-down total-debt-usd BPS total-collateral-usd)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1428-1431)
```text
    ;; Oracle frontrunning protection: prevent same-block liquidation
    ;; This blocks flash-loan based attacks where user borrows + gets liquidated in same block
    (last-borrow-block (get last-borrow-block position))
    (same-block-check (asserts! (not (is-eq last-borrow-block stacks-block-height)) ERR-LIQUIDATION-BORROW-SAME-BLOCK))
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

**File:** local-testing/tests/security/liquidation.test.ts (L153-189)
```typescript
  describe("ATK-LG-05: Bad debt cannot be artificially created", () => {
    it("should socialize bad debt when collateral is exhausted", async () => {
      // Setup: Alice has small collateral, large debt
      txOk(market.collateralAdd(sbtcToken.identifier, 100000000n, null), alice); // 1 sBTC
      txOk(market.borrow(usdcToken.identifier, 42000000000n, null, null), alice); // $42k
      
      // Crash price severely to create bad debt scenario
      // At $10k per BTC: collateral = $10k, debt = $42k (massive underwater)
      await set_price(PythFeedIds.BTC, scalePriceForPyth(10000, -8), -8, deployer);
      
      const charlieSbtcBefore = rov(sbtcToken.getBalance(charlie)).value!;
      
      // Charlie tries to liquidate - will seize all collateral but not cover all debt
      txOk(
        market.liquidate(
          alice,
          sbtcToken.identifier,
          usdcToken.identifier,
          50000000000n, // Try to liquidate $50k (more than debt)
          0n,
          null,
          null
        ),
        charlie
      );
      
      const charlieSbtcAfter = rov(sbtcToken.getBalance(charlie)).value!;
      const collateralSeized = charlieSbtcAfter - charlieSbtcBefore;
      
      // Should have seized all of Alice's collateral (1 BTC)
      expect(collateralSeized).toBeLessThanOrEqual(100000000n);
      
      // Bad debt should be socialized (verified by liquidation succeeding)
      // The protocol handled the bad debt rather than allowing it to corrupt the system
      
      console.log("✓ Bad debt properly socialized when collateral exhausted");
    });
```

**File:** mainnet/contracts/vault/v0-vault-usdh.clar (L942-968)
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
```
