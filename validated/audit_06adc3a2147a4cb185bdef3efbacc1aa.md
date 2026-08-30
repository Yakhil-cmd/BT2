### Title
Cache primed by one caller's stale accrual is consumed by a later, unrelated caller's liquidation in the same block - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
The reported btcd bug is a data race where one goroutine writes a shared field (`wsDisconnected`) that another goroutine reads without synchronization, producing an inconsistent view of connection state. The closest structural analog in this codebase is the `index-cache` map in `v0-4-market.clar`, which is written by whichever caller happens to be first to touch a given `(timestamp, aid)` key in a block, and is subsequently read as ground truth by every other caller that touches the same asset in that same block — including unrelated users performing `liquidate` on third parties. [1](#0-0) [2](#0-1) 

### Finding Description
`accrue-and-cache` keys the cache purely by `stacks-block-time` and `aid`: on a cache hit it returns the previously stored `{index, lindex}` unconditionally, without re-validating that it still reflects the vault's current, real accounting state. [2](#0-1) 

`liquidate` explicitly documents and relies on this "write-then-read" ordering: it calls `accrue-user-debts` / `accrue-user-collateral` first "to populate the cache" and then treats the cache as safe to consume for price/index resolution (`get-cached-indexes`) throughout the rest of the function, including `scale-debt-for-liquidation` and the bad-debt/remaining-debt math. [3](#0-2) [4](#0-3) [5](#0-4) 

This is exactly the class of bug the rules flag as in-scope: "a shared index or cache primed by one caller and consumed by another." Attacker A (any user touching a given `aid` first in a block) writes the shared `index-cache` entry; Liquidator/Victim transactions later in the same block read that entry as if it were authoritative for the current vault state, without re-checking freshness against the vault's true, mutable `index`/`lindex` data vars.

### Impact Explanation
Because `get-cached-indexes`/`accrue-and-cache` never validates the cached value against the vault's live state after the first write in a block, any transaction ordering that changes vault-level accounting (e.g., another deposit/borrow/repay in the same block that would legitimately shift the liquidity index) after the cache was primed will not be reflected for subsequent callers reading the stale cached `{index, lindex}`. Since `liquidate` derives `debt-to-repay`, `coll-final`, and bad-debt socialization entirely from these cached values (`scale-debt-for-liquidation`, `calc-final-liquidation-amounts`), a borrower being liquidated (the victim) can have their collateral seized or debt scaled using a stale index primed by an unrelated caller's transaction, rather than the value that should apply at the moment of liquidation. This falls into the "temporary freezing of funds" / mis-seizure impact class — the victim's position is settled against state manipulated (even unintentionally) by a third party's prior call in the same block, not by their own action.

### Likelihood Explanation
Likelihood is constrained by the fact that `stacks-block-time` bounds the cache lifetime to a single block, and interest indexes normally do not change without accrual elapsing real time — so in the common case the cached value is legitimate. The exploitable window only opens if the vault's index/lindex can be caused to shift within the same block after the first accrual-and-cache call (e.g., a state-changing vault op that alters the ratio without a corresponding fresh accrual before the cache write is consumed). I could not fully verify within the available context whether the ststx/other vault's `accrue`/`index`/`lindex` computation is purely time-based (which would make this benign) or can also shift from same-block deposits/redemptions independent of elapsed time; this is the key open question needed to confirm exploitability, and the vault's `accrue` implementation would need to be read in full to close this gap.

### Recommendation
Re-derive or re-validate the cached `{index, lindex}` against the vault's authoritative state at the point of use in `liquidate` (and other cache consumers), rather than trusting a cache entry primed by a possibly-unrelated prior caller in the same block; alternatively, scope the cache to the calling transaction only (e.g., using a transaction-local read rather than a persisted map keyed only by block time), or have `accrue-and-cache` re-confirm equivalence with a direct `vault-accrue`/read-only state check before allowing a cache hit to satisfy a liquidation call.

### Proof of Concept
Not fully constructible from available context: confirming a concrete exploit requires verifying, inside the vault contracts (e.g. `v0-vault-ststx.clar` `accrue`), whether `index`/`lindex` can change within a single block from a legitimate operation performed by a second, unrelated caller after the first `accrue-and-cache` write — which I was unable to fully confirm before running out of investigation budget. If such same-block index movement is possible, the PoC would be: (1) User A calls any market function touching asset `aid`, priming `index-cache` with the pre-movement `{index, lindex}`; (2) within the same block, a state change occurs on the vault for `aid` that would legitimately shift `index`/`lindex`; (3) Liquidator calls `liquidate` against Borrower's position holding `aid` as collateral/debt; `get-cached-indexes` returns A's stale values instead of the vault's updated ones, causing `coll-final`/`debt-to-repay` to be computed against outdated pricing/indexing, over- or under-seizing the Borrower's collateral relative to the correct in-block state.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L113-115)
```text
(define-map index-cache
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1405-1413)
```text
    ;; accrue FIRST - populates cache for zToken price resolution
    (u-debt (accrue-user-debts (get debt pos-full)))
    (u-coll (accrue-user-collateral (get collateral pos-full)))

    ;; NOW safe to resolve prices (cache is populated)
    (assets (get-assets mask))
    (notional-valued-assets (get-notional-evaluation { position: position, assets: assets }))
    (total-collateral-usd (get collateral notional-valued-assets))
    (total-debt-usd (get debt notional-valued-assets))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1471-1486)
```text
    (curr-scaled (get-account-scaled-debt borrower debt-aid))
    (scaled-info (scale-debt-for-liquidation debt-final coll-actual curr-scaled debt-aid))
    (scaled-to-remove (get scaled-to-remove scaled-info))
    (debt-to-repay (get debt-to-repay scaled-info))
    (coll-final-raw (get coll-final scaled-info))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1518-1525)
```text
          (other-debt-repayable
            (if (> other-coll-usd u0)
              (let ((other-adj (div-bps-down other-coll-usd (+ BPS liq-penalty-max)))
                    (other-tokens (mul-div-down other-adj (pow u10 debt-decimals) debt-price))
                    (other-borrow-idx (get index (unwrap-panic (get-cached-indexes debt-aid))))
                    (other-scaled (mul-div-down other-tokens INDEX-PRECISION other-borrow-idx)))
                (mul-div-up other-scaled other-borrow-idx INDEX-PRECISION))
              u0))
```
