### Title
Stale block-scoped index-cache lets ztoken collateral value bypass same-block debt socialization write-down - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
The market contract caches each vault's `{index, lindex}` pair in `index-cache`, keyed only by `{timestamp: stacks-block-time, aid}` [1](#0-0) . `accrue-and-cache` treats any hit in that map as authoritative for the rest of the block and never re-reads the vault [2](#0-1) . However, `socialize-debt` in each vault contract mutates `lindex` directly via `var-set lindex new-lindex`, completely outside of the `accrue`/`accrue-and-cache` path [3](#0-2) . This is the same bug class as the Erigon fix: a fast-path cache read that is not synchronized with a concurrent write to the same underlying state, so a stale value is served after the authoritative state has already changed.

### Finding Description
`resolve-ztoken`, used to price zSTX/zsBTC/zstSTX/zUSDC/zUSDH/zstSTXbtc collateral, fetches the vault's `lindex` exclusively from `get-cached-indexes`/`index-cache` [4](#0-3) . That cache is populated the first time `accrue-and-cache` is called for a given `(timestamp, aid)` pair in a block, and every subsequent call within the same block returns the cached struct verbatim, without checking whether the vault's on-chain `lindex` has moved since [5](#0-4) .

`socialize-debt` writes down `lindex` to absorb realized bad debt on a vault (haircutting suppliers' liquidity index) [6](#0-5) . It is invoked from the market's liquidation/bad-debt path via `vault-socialize-debt`, which is a routing wrapper independent of `accrue-and-cache` [7](#0-6) . Because `socialize-debt` never touches `index-cache`, any cache entry for that vault's `aid` created earlier in the same block continues to report the pre-socialization (higher) `lindex` for the remainder of the block.

Concretely:
1. In block N, Transaction A (a liquidation that triggers bad-debt socialization on vault-sbtc) first accrues/caches sBTC indexes via `accrue-and-cache`, producing a cache entry `{timestamp: T, aid: sBTC} -> {index, lindex}`. It then calls `vault-socialize-debt`, which writes down the vault's real `lindex` to a lower value, but the already-populated cache entry for timestamp `T` is left untouched.
2. In the same block N, Transaction B — an unrelated user who holds zsBTC as collateral — calls a market operation (borrow, health check, etc.). `resolve-ztoken` calls `get-cached-indexes`/`accrue-and-cache` for `aid = sBTC`, hits the stale cache entry from step 1, and prices zsBTC using the old, higher `lindex` instead of the true, haircut value.
3. Transaction B's health/notional evaluation therefore overvalues the zsBTC collateral, letting that user borrow more than their real collateral supports, or letting an already-unhealthy position evade liquidation for the rest of the block.

The victim here is the shared pool of vault-sbtc suppliers/other borrowers: the socialization loss was supposed to be reflected instantly in every subsequent price computation, but the market's caching layer — a piece of shared state populated by one caller and blindly trusted by another — desynchronizes from the authoritative vault state exactly as `ForkChoiceStore.headHash` desynchronized from `onTickPerSlot`'s write in the Erigon report.

### Impact Explanation
This lands in the "temporary freezing/mispricing leading to protocol insolvency" bucket: a borrower can extract debt against overstated zToken collateral within the same block a socialization event occurs, or a genuinely unhealthy position can dodge liquidation for that block, both of which directly increase realized bad debt socialized onto the vault's suppliers — a harm inflicted by one unprivileged principal (the borrower who benefits from the stale cache, or whoever triggers the qualifying sequence) onto another unprivileged principal (the vault's supplier pool), satisfying the "socialization charged to all suppliers" and "position made unevaluable/mispriced by a third party" criteria.

### Likelihood Explanation
Requires (a) a bad-debt socialization event and (b) a subsequent market transaction touching the same vault's ztoken within the identical block/timestamp. Socialization is triggered by market-controlled liquidation logic (not attacker-controlled arbitrarily), and ordering within a block is influenced by mempool/miner ordering rather than the attacker directly, which lowers but does not eliminate likelihood — a user (or the liquidator itself, front-running/back-running their own liquidation call) could deliberately place a second transaction in the same block to exploit the stale cache window.

### Recommendation
Invalidate or update the relevant `index-cache` entry inside `socialize-debt`'s call path (or have `vault-socialize-debt` return the fresh `{index, lindex}` and have the market immediately `map-set` it into `index-cache` for the current timestamp), so that any subsequent `accrue-and-cache`/`resolve-ztoken` call within the same block observes the post-socialization state rather than a stale cached copy.

### Proof of Concept
Not independently executable without a live/test harness; described as a sequenced scenario above (Tx A: liquidation → `vault-socialize-debt` write-down of `lindex` after `accrue-and-cache` already cached the pre-write value for the block's timestamp; Tx B same block: `resolve-ztoken` for the same `aid` reads the stale cached `lindex`). Confirming exploitability end-to-end (i.e., that a borrow/health-check reachable in the same block can actually leverage the stale price for profit) would require running the local test suite (`local-testing/tests/security/authorization.test.ts` and related liquidation tests) against this exact sequence, which was not verified within this session.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L116-118)
```text

;; -- Oracle timestamp tracking
(define-map last-update
```

**File:** mainnet/contracts/market/v0-4-market.clar (L216-223)
```text
(define-private (vault-socialize-debt (aid uint) (amount uint))
  (if (is-eq aid STX) (contract-call? .v0-vault-stx socialize-debt amount)
  (if (is-eq aid sBTC) (contract-call? .v0-vault-sbtc socialize-debt amount)
  (if (is-eq aid stSTX) (contract-call? .v0-vault-ststx socialize-debt amount)
  (if (is-eq aid USDC) (contract-call? .v0-vault-usdc socialize-debt amount)
  (if (is-eq aid USDH) (contract-call? .v0-vault-usdh socialize-debt amount)
  (if (is-eq aid stSTXbtc) (contract-call? .v0-vault-ststxbtc socialize-debt amount)
  ERR-UNKNOWN-VAULT)))))))
```

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

**File:** mainnet/contracts/market/v0-4-market.clar (L343-347)
```text
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L944-968)
```text
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
