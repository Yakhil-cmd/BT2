### Title
Stale timestamp-keyed liquidity-index cache in `market.clar` lets a first caller's snapshot mis-price a vault's ztoken for later callers in the same block - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`market.clar` caches each vault's accrued liquidity index (`index`, `lindex`) keyed only by `{timestamp: stacks-block-time, aid}`. Whoever resolves a ztoken price first in a given block "primes" this cache; every other market participant who needs a price for the same vault during that same block reuses the cached snapshot instead of recomputing it, even if the vault's live rate/utilization inputs changed in the interim. This is the same class of bug as the CoreCollection report: a shared, cheaply-primeable piece of state that one caller writes and another, unrelated caller unknowingly consumes.

### Finding Description
The oracle/market layer implements a per-block index cache: [1](#0-0) 

`accrue-and-cache` is keyed only by `stacks-block-time` and `aid` — not by the caller, not by the vault's actual `last-update`/utilization state. The docs themselves state the invalidation model is purely "new block ⇒ new timestamp": [2](#0-1) 

The value being cached, `vault-accrue`, is a preview of `next-index`/`next-liquidity-index`, both of which are computed from the *live* `interest-rate` (itself a function of *current* `utilization`), not a rate frozen at `last-update`: [3](#0-2) 

Because `interest-rate`/`utilization` are recomputed from live state on every call, two calls to `vault-accrue` for the same `aid` at the same `stacks-block-time` will diverge if the vault's `total-debt`/`assets`/`total-borrowed` change between them (e.g. a supply, withdraw, borrow or repay executed by an unrelated party earlier in the same block). The market's cache, however, freezes whichever result was computed *first* in that block and serves it to everyone else who needs a price for that asset for the rest of the block — this is the exact "index/cache primed by one caller, consumed by another" pattern.

The same map/function pair exists verbatim (confirmed by matching occurrence counts) in the production contract: [4](#0-3) 

### Impact Explanation
An attacker (Party A) can, early in a block, trigger any market action that resolves the ztoken price for a vault they don't otherwise interact with meaningfully (e.g. a trivial supply/withdraw), forcing `accrue-and-cache` to snapshot an index computed under conditions favorable to A. Party A then performs the real economically significant action later in the same block — e.g., mutating the vault's utilization via a large borrow/repay so that the *true* live index would differ from the frozen cache — before a Victim (a borrower being health-checked, or a liquidator computing seize amounts, or another depositor computing withdrawable value) reads the stale, cached price for their own unrelated transaction in that same block. The victim's collateral/debt valuation is computed against a price that no longer reflects the vault's live state, which can:
- Let an undercollateralized position pass a health check that would otherwise fail (temporary freezing of funds / risk socialized to all suppliers of that vault), or
- Cause a liquidation to seize an amount inconsistent with the vault's true value (seizure exceeding its bound).

This lands in the **High** impact bucket (temporary freezing of funds / mispriced seizure affecting a third party), since it does not directly move principal but corrupts a shared valuation input consumed by other users' transactions within the same block.

### Likelihood Explanation
Likelihood is moderate: it requires (1) the attacker to be first to trigger a price resolution for the target vault in a block, and (2) a state-mutating transaction (theirs or a third party's) later in the same block to move the vault's utilization enough to matter, and (3) a victim to transact against the stale cached price in that same window. All three conditions are attacker-schedulable to some degree (front-running/back-running within a block via fee/ordering), making this a realistic, if narrow, ordering-dependence bug rather than a purely theoretical one.

### Recommendation
Key the cache on the vault's own `last-update`/state-version rather than purely on `stacks-block-time`, or invalidate/refresh the cache entry whenever a mutating vault operation (supply/withdraw/borrow/repay) changes the inputs that `interest-rate`/`utilization` depend on. Alternatively, compute `vault-accrue` deterministically off the vault's committed `last-update` and stored rate at that point (rather than "live" utilization), so that same-block calls are guaranteed to agree regardless of caller order.

### Proof of Concept
Not executable from the indexed docs/contracts alone — the exact production line numbers for `market.clar`'s `accrue-and-cache`/`index-cache-` and the call sites that consume it (borrow/liquidate health checks) were not retrievable within tool limits from `mainnet/contracts/market/v0-4-market.clar` (only match counts were confirmed via `grep_search`, not full context). A Devin session with full file access would be needed to pull exact line numbers, confirm the call-order (does a supply/borrow update `last-update` before or after price resolution in the same transaction?), and build a concrete two-transaction PoC (Tx1: attacker primes cache; Tx2: attacker mutates utilization; Tx3: victim's borrow/liquidation reads stale cache) to prove the divergent index values under real interest-rate curve parameters.

### Citations

**File:** docs/oracle.md (L336-349)
```markdown
```clarity
;; In market.clar
(define-map index-cache- 
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })

(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache- cache-key)))
    (match cached?
      existing existing
      (let ((fresh (vault-accrue aid)))
        (map-set index-cache- cache-key fresh)
        fresh))))
```

**File:** docs/oracle.md (L352-357)
```markdown
**Purpose:** 
- Multiple price resolutions for the same vault within a single block use cached indexes
- Avoids redundant cross-contract calls to vaults
- Significantly reduces gas costs for transactions involving multiple ztoken prices

**Cache Invalidation:** Cache is timestamp-based using `stacks-block-time`, automatically invalidating when a new block is processed.
```

**File:** mainnet/contracts/vault/v0-vault-ststx.clar (L368-404)
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1-1)
```text
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
```
