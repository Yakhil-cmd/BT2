### Title
Stale timestamp-keyed liquidity-index cache lets a ztoken depositor be undervalued by a same-block borrower's rate-changing action - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
`market.clar`'s `accrue-and-cache` memoizes each vault's `{index, lindex}` under a `{timestamp: stacks-block-time, aid}` key and never invalidates within a block. [1](#0-0)  Because `stacks-block-time` is constant for the whole block, once any account's transaction primes the cache for a given `aid`, every later transaction in the same block that touches that asset — even a different, unrelated account — reads the memoized value instead of re-deriving it from the vault's live state.

### Finding Description
`next-index`/`next-liquidity-index` in the vault contracts (e.g. `v0-vault-sbtc.clar`) compute the accrued index from `interest-rate()`, which itself depends on `utilization()` — a function of `total-borrowed`/`available-assets` at call time, not purely elapsed time. [2](#0-1)  The vault's own `accrue` recomputes `next`/`nliq` from current utilization every time it is invoked directly. [3](#0-2) 

`market.clar`, however, treats the first `vault-accrue` result observed in a block as authoritative for that whole block and caches it keyed only by `(timestamp, aid)`: subsequent `accrue-and-cache` calls for the same `aid` in the same block return the cached tuple unconditionally, without re-checking whether the vault's `total-borrowed`/utilization has since changed via a direct vault call (`system-borrow`, `deposit`, `redeem`, etc. through the market or vault directly) that occurred between the two market-mediated operations. [1](#0-0)  This cache is consumed both for debt accrual (`accrue-debt-asset`) and for zToken collateral pricing (`accrue-collateral-asset` / the LTV-capacity check in `collateral-add`). [4](#0-3) [5](#0-4) 

Attacker/victim pattern: User B (victim) performs a market operation (e.g. `collateral-add` using a ztoken, or a health/liquidation check) that depends on `accrue-and-cache` for vault X. If User A (attacker/unrelated party) had already, earlier in the same block, caused `accrue-and-cache` for vault X to be primed with a stale `{index, lindex}` — for instance by triggering the market's accrual path before executing an action that changes utilization (e.g., `system-borrow` through the market, which also calls `accrue` first) — then B's subsequent read within the same block gets the value computed at A's pre-borrow utilization rather than the value that would result from re-deriving off the vault's now-changed state. This is a "shared cache primed by one caller and consumed by another" situation: the shared state is the `index-cache` map, and the two unrelated principals are A (who unknowingly or deliberately primes it) and B (whose collateral valuation/LTV capacity check or debt accrual then relies on the frozen figure for the rest of the block).

### Impact Explanation
If the cached index understates the true post-utilization-change liquidity/debt index for the remainder of the block, a zToken collateral valuation performed via `get-asset-value`/`get-notional-evaluation` for User B could be computed off a stale, lower (or higher) index than the vault's actual live state would produce, affecting the LTV capacity check in `collateral-add` (`ERR-UNHEALTHY` gate at line 1099 of `v0-4-market.clar`). [6](#0-5)  A borrower whose health/liquidation eligibility is evaluated in the same block right after another account's action primed the cache could be permitted to borrow against, or be spared liquidation on, stale collateral/debt valuations — a temporary mispricing of funds within that block. This falls under "temporary freezing/mispricing of funds" (High) rather than a direct steal, since the cache always resets on the next block/timestamp and the discrepancy window is bounded to a single block.

### Likelihood Explanation
Likelihood is low-to-moderate: it requires two market-touching transactions on the same vault asset landing in the same block, with the first materially changing utilization (via borrow/repay/deposit/redeem) after the cache was already primed for that timestamp, and the second relying on the now-stale cached index for a security-relevant check (LTV capacity or liquidation health). This is achievable by a single actor sequencing two of their own transactions plus a victim's transaction, or opportunistically by mempool ordering, but is not a straightforward "any single unprivileged caller harms themselves" pattern — it depends on shared per-block cache state and transaction ordering, matching the analog criteria in the prompt.

### Recommendation
Either (a) invalidate/refresh the `index-cache` entry whenever a vault's `total-borrowed`, `assets`, or `principal-scaled` changes within the block (e.g., bump a per-vault "state version" into the cache key), or (b) always re-derive from the vault's current live state for any check that gates borrowing capacity or liquidation eligibility (`collateral-add`, health checks), only using the cache for pure gas-optimization paths where staleness cannot affect a solvency/LTV decision.

### Proof of Concept
1. In block N, User A calls a market operation on vault X (e.g., `borrow`) that internally calls `vault-accrue`/`accrue-and-cache` for `aid = X`, populating `index-cache { timestamp: stacks-block-time, aid: X }` with the index/lindex computed at A's pre-borrow utilization, then completes the borrow, changing `total-borrowed` for vault X.
2. Still in block N, User B calls `collateral-add` with a zX ztoken as new collateral. `collateral-add`'s capacity check calls `accrue-and-cache vault-id` for the same `aid = X`; because the cache entry for `{timestamp, X}` already exists (set in step 1), the cache HIT path in `accrue-and-cache` returns A's stale indexes instead of re-deriving from vault X's now-higher-utilization state. [1](#0-0) [7](#0-6) 
3. B's `future-capacity` check in `collateral-add` is computed against the stale index, potentially passing (or failing) a check that would give a different result off live vault state, illustrating a cache primed by A and silently consumed to B's detriment or unwarranted benefit within the same block.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L245-257)
```text
(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache cache-key)))

    (match cached?
      ;; cache HIT: return cached value (1 read only)
      cached-indexes (ok cached-indexes)

      ;; cache MISS: accrue and cache (vault-accrue now returns indexes)
      (let ((indexes (try! (vault-accrue aid))))
        ;; store in cache
        (map-set index-cache cache-key indexes)
        (ok indexes)))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L270-302)
```text
(define-private (accrue-user-collateral (coll-list (list 64 {aid: uint, amount: uint})))
  (fold accrue-collateral-asset coll-list { success: true }))

(define-private (accrue-collateral-asset
  (coll-entry { aid: uint, amount: uint })
  (acc { success: bool }))
  (let ((aid (get aid coll-entry)))
    ;; Only accrue if asset is a registered ztoken
    (if (is-ztoken aid)
        ;; ZToken: map to underlying vault routing ID and accrue
        ;; zSTX(1)->STX(0), zsBTC(3)->sBTC(2), zstSTX(5)->stSTX(4), zUSDC(7)->USDC(6), zUSDH(9)->USDH(8), zstSTXbtc(11)->stSTXbtc(10)
        (let ((vault-id (if (is-eq aid zSTX) STX
                        (if (is-eq aid zsBTC) sBTC
                        (if (is-eq aid zstSTX) stSTX
                        (if (is-eq aid zUSDC) USDC
                        (if (is-eq aid zUSDH) USDH
                        (if (is-eq aid zstSTXbtc) stSTXbtc
                        ;; will cause ERR-UNKNOWN-VAULT with any value over 64
                        u100))))))))
          (begin
            (unwrap-panic (accrue-and-cache vault-id))
            acc))
        ;; Non-ztoken: skip accrual (no liquidity index needed)
        acc)))

;; -- Oracle: external price feeds -------------------------------------------

(define-private (normalize-pyth (p int) (expo int))
  (let ((adj (+ expo 8))
        (inkind? (asserts! (not (is-eq adj 0)) (to-uint p)))
        (res (if (> adj 0)
                (* p (pow 10 adj))
                (/ p (pow 10 (- adj))))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1051-1104)
```text
                    (current-assets (get-assets current-mask))
                    (current-notional (get-notional-evaluation { position: position, assets: current-assets }))
                    (current-debt-usd (get debt current-notional)))

                ;; ONLY check capacity if user has debt
                (if (> current-debt-usd u0)
                    ;; Calculate future mask and validate egroup exists
                    (let ((current-coll-usd (get collateral current-notional))
                          (current-capacity (* current-coll-usd current-ltv))
                          ;; Prime cache for new zToken collateral underlying if not already cached
                          (cache-primed (if (is-ztoken asset-id)
                                            (let ((vault-id (if (is-eq asset-id zSTX) STX
                                                            (if (is-eq asset-id zsBTC) sBTC
                                                            (if (is-eq asset-id zstSTX) stSTX
                                                            (if (is-eq asset-id zUSDC) USDC
                                                            (if (is-eq asset-id zUSDH) USDH
                                                            (if (is-eq asset-id zstSTXbtc) stSTXbtc
                                                            u100))))))))
                                              (try! (accrue-and-cache vault-id)))
                                            { index: u0, lindex: u0 }))
                          (added-collateral-value (try! (get-asset-value asset amount false)))
                          (future-ltv (buff-to-uint-be (get LTV-BORROW future-group)))
                          (future-coll-usd (+ current-coll-usd added-collateral-value))
                          (future-capacity (* future-coll-usd future-ltv)))
                      ;; CRITICAL CHECK: Future capacity must not decrease
                      (asserts! (>= future-capacity current-capacity) ERR-UNHEALTHY))
                    ;; No debt - skip capacity check
                    true))
              
              ;; Not new collateral - skip all checks (safe to add more)
              true))
      
      new-user-error-code
        ;; New user - validate that the new future mask is in a valid egroup
        (begin
          (try! (get-egroup (pow u2 asset-id)))
          true))

    ;; Execute collateral add (existing logic)
    (let ((result (try! (contract-call? .v0-market-vault collateral-add account amount ft asset-id))))
      
      (print {
        action: "collateral-add",
        caller: contract-caller,
        data: {
          account: account,
          asset-id: asset-id,
          asset-addr: ft-address,
          amount: amount,
          updated-collateral-amount: result
        }
      })
      
      (ok result))))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L366-402)
```text
(define-private (utilization)
  (calc-utilization (get-available-assets) (total-debt)))

(define-private (interest-rate)
  (let ((points-data (var-get points-ir))
        (uword (get util points-data))
        (rword (get rate points-data))
        (utils (unpack-u16 uword))
        (rates (unpack-u16 rword)))
    (interpolate-rate (utilization) utils rates)))

(define-private (next-index)
  (let ((states (var-get pause-states))
        (idx (var-get index)))
    (if (get accrue states)
        idx
        (let (
            (rate (interest-rate))
            (time-delta (- stacks-block-time (var-get last-update)))
            (multiplier (if (is-eq time-delta u0)
                          INDEX-PRECISION
                          (calc-multiplier-delta rate time-delta true))))
          (calc-index-next idx multiplier)))))

(define-private (next-liquidity-index)
  (let ((states (var-get pause-states))
        (lidx (var-get lindex)))
    (if (get accrue states)
        lidx
        (let (
            (rate (interest-rate))
            (liquidity-rate (calc-liquidity-rate rate (utilization) (var-get fee-reserve)))
            (time-delta (- stacks-block-time (var-get last-update)))
            (multiplier (if (is-eq time-delta u0)
                          INDEX-PRECISION
                          (calc-multiplier-delta liquidity-rate time-delta false))))
          (calc-index-next lidx multiplier)))))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L833-861)
```text
(define-public (accrue)
  (let ((states (var-get pause-states))
        (idx (var-get index))
        (lidx (var-get lindex)))
      (if (get accrue states)
          ;; PAUSED: Pass-through without reverting
          (ok { index: idx, lindex: lidx })
          ;; NOT PAUSED: Normal accrual logic
          (let ((next (next-index))
                (nliq (next-liquidity-index))
                (scaled-principal (var-get principal-scaled))
                (old-debt (mul-div-down scaled-principal idx INDEX-PRECISION))
                (new-debt (mul-div-down scaled-principal next INDEX-PRECISION))
                (debt-delta (if (> new-debt old-debt) (- new-debt old-debt) u0))
                (reserve-inc (mul-div-down debt-delta (var-get fee-reserve) BPS))
                (treasury-lp (if (> reserve-inc u0) (mul-div-down reserve-inc (total-supply) (- (total-assets-preview) reserve-inc)) u0)))
            (if (not (is-eq idx next))
                (var-set index next)
                false)
            (if (not (is-eq lidx nliq))
                (var-set lindex nliq)
                false)
            (if (> treasury-lp u0)
                (try! (ft-mint? zft treasury-lp .dao-treasury))
                false)
            (if (or (not (is-eq idx next)) (not (is-eq lidx nliq)))
                (var-set last-update stacks-block-time)
                false)
            (ok { index: next, lindex: nliq })))))
```
