### Title
Stale market-level index cache lets a socialize-debt write-down be invisible to other users' health checks in the same block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
The market contract memoizes vault accrual results per block via a shared `index-cache` map keyed only by `{timestamp, aid}` [1](#0-0) . `accrue-and-cache` treats any cache hit as authoritative and skips calling the vault again [2](#0-1) . However, a vault's `socialize-debt` entry point directly mutates the vault's `lindex` state variable (`var-set lindex new-lindex`) completely outside of the `accrue`/`accrue-and-cache` path [3](#0-2) . Once the market has cached `{index, lindex}` for a given `(timestamp, aid)` earlier in a block, a subsequent `socialize-debt` write-down for that same asset does not invalidate the cache, so every other user whose collateral/debt is evaluated later in the same block via `accrue-user-collateral`/`accrue-user-debts` receives the stale, pre-write-down `lindex`/`index` [4](#0-3) .

### Finding Description
`accrue-and-cache` is the single choke point the market uses to accrue and memoize each vault's `{index, lindex}` once per Stacks block time, for both debt (`accrue-user-debts`) and zToken collateral (`accrue-user-collateral`) evaluation [5](#0-4) . This is the shared state analogous to the CCTP `HAS_BEFORE_BEEN_CALLED_SLOT`: it is primed by whichever transaction happens to accrue first in a block, and blindly consumed ("cache HIT: return cached value ... 1 read only") by every subsequent transaction in that same block.

The vault's `socialize-debt`, which is invoked to write down bad debt (e.g., after an under-collateralized liquidation shortfall), bypasses this shared cache entirely: it reads `lindex`/`index` from vault state, computes a reduced `new-lindex`, and calls `var-set lindex new-lindex` directly, with no interaction with the market's `index-cache` map [6](#0-5) . If, earlier in the same block, any market call already populated `index-cache` for that `(timestamp, aid)` (e.g. via a borrow, repay, or another user's liquidation that called `accrue`), the cache retains the pre-write-down value for the rest of the block.

Any other user's position evaluated afterward in the same block - e.g., a liquidator checking a third party's health, or the market computing collateral value for a different borrower's zToken collateral - goes through `accrue-user-collateral`/`accrue-user-debts` → `accrue-and-cache`, hits the stale cache, and values that asset using the pre-socialization (higher) `lindex`, understating the real loss that was just recognized in the vault [7](#0-6) .

### Impact Explanation
`lindex` written by `socialize-debt` directly determines the conversion rate from zToken shares to underlying assets, and is exactly the value a market health check needs to correctly price a position's zToken collateral or an account's underlying debt. Because the market's `index-cache` is not invalidated by `socialize-debt`, an unrelated user's health/liquidation evaluation in the same block can be computed with an overstated `lindex`, causing zToken collateral to be overvalued and debt to be undervalued relative to the vault's true post-write-down state. This can (a) let a liquidator fail to liquidate a position that is actually unhealthy once the true write-down is accounted for (temporary freezing of the ability to recognize/collect bad debt), or (b) let an actually-unhealthy borrower's position pass a health check and continue to borrow/withdraw against collateral that is really worth less, directly harming the pool's solvency and other depositors/lenders whose funds back that debt.

### Likelihood Explanation
This requires two market-facing calls to land in the same Stacks block for the same asset id: one that primes `index-cache` (any deposit/borrow/repay/liquidation touching that vault) and one `socialize-debt` call plus a third user's health-affecting operation reading the stale cache. Socialize-debt is a guardian/system-triggered path following a liquidation shortfall, so this is not attacker-arbitrary, but it is a realistic sequencing since liquidations frequently trigger both an accrual (via the liquidation's own health check) and, if there's a shortfall, `socialize-debt`, all within the same block, with other market interactions (other liquidators, other borrowers) plausible in the same block on a busy chain.

### Recommendation
Invalidate or update the market's `index-cache` entry for `(stacks-block-time, aid)` whenever `socialize-debt` (or any other vault function that mutates `index`/`lindex` outside of `accrue`) runs, or have `socialize-debt` return the updated indexes so the market can `map-set` the cache immediately, mirroring the recommendation from the CCTP report to keep the shared cache/slot consistent with every state-mutating call rather than only the first one per block.

### Proof of Concept
1. Block N: User A borrows USDC, triggering `v0-4-market` → `accrue-and-cache(USDC)` → cache MISS → `vault-accrue` runs, `index-cache[{timestamp: T, aid: USDC}]` is set to `{index: I1, lindex: L1}` [2](#0-1) .
2. Still in block N: a liquidation of an insolvent position on the USDC vault triggers `vault-socialize-debt(USDC, scaledAmount)` → `socialize-debt` writes `lindex` down to `L2 < L1` directly in vault state, with no update to `index-cache` [3](#0-2) .
3. Still in block N: User B's position, which holds zUSDC collateral, is evaluated (e.g., by a liquidator checking health, or by User B themselves withdrawing/borrowing more). This calls `accrue-user-collateral` → `accrue-and-cache(USDC)` → cache HIT → returns stale `{index: I1, lindex: L1}` instead of the vault's true current `L2` [7](#0-6) .
4. User B's zUSDC collateral is valued using `L1` instead of the true `L2`, overstating their collateral value for the remainder of block N and potentially masking insolvency or blocking a valid liquidation.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L112-115)
```text
;; -- Index cache (for accrual)
(define-map index-cache
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })
```

**File:** mainnet/contracts/market/v0-4-market.clar (L245-293)
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

(define-private (accrue-user-debts (debt-list (list 64 { aid: uint, scaled: uint})))
  (fold accrue-debt-asset debt-list { success: true }))

(define-private (accrue-debt-asset
  (debt-entry { aid: uint, scaled: uint })
  (acc { success: bool }))
  (begin
    ;; this will use cache if available, accrue if not
    (unwrap-panic (accrue-and-cache (get aid debt-entry)))
    acc))

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
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L942-964)
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
