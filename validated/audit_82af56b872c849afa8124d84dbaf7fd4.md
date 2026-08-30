### Title
Stale Market Index Cache From Direct Vault Calls Corrupts Debt Accounting for Other Users in the Same Block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
The market contract caches vault liquidity/borrow indexes in a shared, block-scoped map `index-cache` keyed only by `{timestamp, aid}`, not by caller. Because the underlying vault's `accrue`, `deposit`, and `redeem` functions are `public` and can be called directly by any unprivileged user (bypassing the market), any user can mutate a vault's real index after the market has already cached a value for that block. Every other user whose market transaction executes afterward in the same block will read the stale cached index instead of the vault's true current index, corrupting debt/collateral valuation for their positions.

### Finding Description
`accrue-and-cache` in `v0-4-market.clar` implements a cache-then-return pattern shared globally across all callers within a block: [1](#0-0) 

The cache key is `{ timestamp: stacks-block-time, aid: aid }` — it has no dependency on which caller populated it or on the vault's actual on-chain index at read time; a cache HIT is trusted blindly:
```
(match cached?
  cached-indexes (ok cached-indexes)     ;; trusted without re-checking vault state
  ...)
```

Meanwhile, the vaults' `accrue`, `deposit`, and `redeem` are all `public` entry points, independently callable by any address without going through the market: [2](#0-1) [3](#0-2) 

Each of these vault calls internally recomputes and stores a fresh `index`/`lindex` in the vault's own state (`var-set index next`, `var-set lindex nliq`), independent of whether the market has already cached an (older) index for that block.

**Attack flow (single block):**
1. Victim/attacker A performs a market operation (e.g., `collateral-add` or `borrow`) touching asset `aid`. This triggers `accrue-and-cache`, which is a cache MISS, so it calls `vault-accrue` and stores the resulting `{index, lindex}` into `index-cache` for `{timestamp, aid}`.
2. Attacker B calls the vault contract for `aid` directly (`deposit`, `redeem`, or `accrue`) in the same block. This bumps the vault's real `index`/`lindex` state variables, but does **not** touch or invalidate the market's `index-cache` entry.
3. Victim C then performs a market operation depending on `aid` in the same block (e.g., health check, borrow, liquidation via `scale-debt-for-liquidation`, which explicitly reads `get-cached-indexes`): [4](#0-3) 
Victim C's debt/collateral math is computed against the stale index cached in step 1, not the vault's real current index set in step 2.

### Impact Explanation
Debt is scaled and unscaled using `borrow-index` sourced from this cache in `scale-debt-for-liquidation`, and collateral/debt USD valuations elsewhere in the market rely on the same cached indexes. A stale (lower) cached index used for debt-to-repay computations, borrow capacity checks, or liquidation math causes systemic mispricing of positions for parties who did not cause the staleness — this is a shared-state bug between two unprivileged principals (the direct vault caller vs. market callers in the same block), not a self-only issue. Depending on direction of drift, this can let a borrower under-repay real vault debt (socializing a loss onto all suppliers of that vault, since the vault's real assets/liabilities diverge from what the market ledger believes), or cause a victim's legitimate operation (borrow/withdraw/liquidation) to be computed on wrong values, producing incorrect liquidation outcomes or temporarily blocking valid operations. This lands on: **temporary freezing of funds** and **socialization charged to all suppliers** of the affected vault, both in-scope impact classes.

### Likelihood Explanation
This requires no privilege and no DAO compromise — any address can call a vault's public `accrue`/`deposit`/`redeem` directly, and any two market users' ordinary transactions landing in the same block are enough to trigger the divergence. It does not require a flashloan or governance interaction. Likelihood is elevated on Stacks given multiple transactions commonly land in the same block, and the vaults expose these entry points publicly by design for direct deposit/withdrawal.

### Recommendation
Do not trust a block-scoped cache HIT unconditionally. Either (a) invalidate/refresh the market's `index-cache` entry whenever the corresponding vault's `accrue`/`deposit`/`redeem` is invoked directly (e.g., via a callback into market, or by having vaults be the sole source of truth queried live rather than cached), or (b) key the cache validity off a monotonic per-vault version/index value rather than block timestamp so any external state change forces a cache miss, or (c) remove direct public access to vault `accrue`/`deposit`/`redeem` and route all such calls exclusively through the market so `index-cache` is always kept consistent with the vault state that produced it.

### Proof of Concept
1. Block N, tx 1 (Alice, market): `market.collateral-add(...)` for asset `aid=STX` → cache MISS → `accrue-and-cache` calls `vault-accrue`, caches `{index: I0, lindex: L0}` at `{timestamp: T, aid: STX}`.
2. Block N, tx 2 (Bob, direct vault call): `vault-stx.deposit(...)` (public) → internally calls `accrue` → vault state updates to `{index: I1, lindex: L1}` (I1 != I0). Market's `index-cache` for `{T, STX}` is untouched, still `{I0, L0}`.
3. Block N, tx 3 (Carol, market): `market.borrow(...)` or `market.liquidate(...)` involving `STX` → `accrue-and-cache` is a cache HIT → returns stale `{I0, L0}` → `scale-debt-for-liquidation`/debt math computed against `I0` instead of the vault's true `I1`, producing an inconsistent debt/collateral outcome for Carol relative to the vault's real accounting.

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

**File:** mainnet/contracts/market/v0-4-market.clar (L858-877)
```text
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

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L795-833)
```text
(define-public (redeem (amount uint) (min-out uint) (recipient principal))
  (let (
    (states (var-get pause-states))
    (u (try! (accrue)))
    (account contract-caller)
    (current-assets (var-get assets))
    (balance (get-balance-internal account))
    (balance-check (asserts! (>= balance amount) ERR-INSUFFICIENT-BALANCE))
    (available-assets (get-available-assets))
    (inkind (convert-to-assets-preview amount)))

  (asserts! (>= current-assets inkind) ERR-INSUFFICIENT-ASSETS)
  (asserts! (not (get redeem states)) ERR-PAUSED)
  (asserts! (> amount u0) ERR-AMOUNT-ZERO)
  (asserts! (> inkind u0) ERR-OUTPUT-ZERO)
  (asserts! (>= inkind min-out) ERR-SLIPPAGE)
  (asserts! (>= available-assets inkind) ERR-INSUFFICIENT-LIQUIDITY)

  (try! (ft-burn? zft amount account))
  (try! (send-underlying inkind recipient))
  (var-set assets (- current-assets inkind))

  (print {
    action: "redeem",
    caller: contract-caller,
    data: {
      redeemer: account,
      recipient: recipient,
      shares-burned: amount,
      amount-received: inkind,
      assets: (- current-assets inkind)
    }
  })

  (ok inkind)))

;; -- Lending operations -----------------------------------------------------

(define-public (accrue)
```

**File:** mainnet/contracts/vault/v0-vault-ststx.clar (L835-865)
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

(define-public (system-borrow (amount uint) (receiver principal))
```
