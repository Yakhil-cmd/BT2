### Title
`oracle-timestamp-fresh` accepts future price timestamps and can permanently poison the monotonic `last-update` cache, freezing price resolution for all users of an asset - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`oracle-timestamp-fresh` in the market contract does not reject an oracle publish-time that lies in the future relative to `stacks-block-time`. Instead of reverting (the analog of `_blockNumber > block.number` in the reported bug), it silently clamps the staleness delta to `u0`, treating a future timestamp as perfectly fresh. Because the same function's monotonic check writes that future timestamp into a shared, per-asset `last-update` map that every subsequent caller's price resolution depends on, one transaction that surfaces a future-dated Pyth/DIA update can lock out all other users from resolving that asset's price until real chain time catches up to the poisoned value.

### Finding Description
`oracle-timestamp-fresh` is defined as: [1](#0-0) 

```clarity
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))
```

If `ts > stacks-block-time` (the oracle-reported publish time is in the future relative to the current block), `delta` is forced to `u0`, which always passes the `<= delta max-staleness` check — the exact class of bug flagged in the external report (accepting a value beyond the current chain reference point instead of reverting). This function feeds directly into `price-resolve`: [2](#0-1) 

```clarity
(define-private (price-resolve
  (data { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint }))
  (let (...
        (last-update-time (oracle-last-update key))
        (timestamp (get timestamp resolution))
        ...)
    (asserts! (and (oracle-price-legal final-price) (oracle-timestamp-fresh timestamp last-update-time max-staleness))
              ERR-ORACLE-INVARIANT)
    (if (> timestamp last-update-time)
        (map-set last-update key timestamp)
        false)
    (ok final-price)))
```

The `last-update` map is a single, shared per-`{type, ident}` value consulted by every future call to `price-resolve` for that asset (used in borrow, withdraw, and liquidation flows across the whole market). Once any caller's transaction surfaces an oracle price whose `publish-time` is ahead of the current `stacks-block-time` (this can happen from ordinary Pyth/DIA clock drift, or from an attacker deliberately relaying a signed update they hold with the largest available `publish-time`), that future value is written into `last-update` because `timestamp > last-update-time` is satisfied trivially the first time. From that point forward, *every other user's* price resolution for that asset must satisfy `(>= ts prev)` against the poisoned future `prev`. Any legitimately-timestamped (i.e., real, non-future) update will have `ts < prev` and fail this check, reverting with `ERR-ORACLE-INVARIANT` for every account that would otherwise need a valid price for that asset — until real chain time advances past the poisoned future timestamp.

### Impact Explanation
Because `last-update` is shared state consumed by all borrowers/depositors/liquidators of the affected asset (not just the caller who supplied the future timestamp), this is not merely self-harm: one unprivileged caller's transaction can freeze price resolution — and therefore borrow, withdraw, and liquidation operations that depend on that asset's price — for every other user of the market until the poisoned timestamp is reached. This is a temporary freezing-of-funds condition (users cannot withdraw/borrow/liquidate positions dependent on that asset's price while the cache is poisoned), landing in the in-scope "temporary freezing of funds" impact class. If the injected timestamp is set far enough in the future, the freeze duration can be made very long, aggravating severity toward blocking legitimate liquidations (risking insolvency exposure while positions cannot be liquidated).

### Likelihood Explanation
Triggering the condition only requires a single call path (`price-resolve`) to observe an oracle timestamp greater than `stacks-block-time`, which the code accepts unconditionally by clamping `delta` to zero rather than rejecting the update. This can occur from benign oracle/publisher clock skew (which the current freshness threshold — 120 seconds cardinality per `docs/oracle.md` — does not protect against once the check is bypassed by the `> ts stacks-block-time` clamp) or be intentionally engineered by any user relaying/triggering a price update with the most future-leaning valid publish-time available to them. No privileged role is required to trigger it; it fires within the normal, permissionless `price-resolve` path used by ordinary market operations.

### Recommendation
`oracle-timestamp-fresh` should reject (revert) rather than clamp when `ts > stacks-block-time`, mirroring the recommended fix for the analogous `_blockNumber > block.number` issue:

```clarity
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (and
    (<= ts stacks-block-time)                 ;; reject future timestamps outright
    (<= (- stacks-block-time ts) max-staleness)
    (>= ts prev)))
```

This ensures a future-dated publish time is never written into the shared `last-update` map, preventing any single caller from being able to poison price resolution for the rest of the market.

### Proof of Concept
1. Oracle relaying: any user calls a market operation (e.g., `deposit`/`borrow`) that triggers `price-resolve` for asset `X` using a Pyth/DIA response whose `publish-time` (`ts`) is greater than the current `stacks-block-time` (this can occur naturally from oracle publisher clock skew, or be chosen deliberately by relaying the highest-timestamp valid signed update available).
2. In `oracle-timestamp-fresh`, since `ts > stacks-block-time`, `delta` is set to `u0`, so `(<= delta max-staleness)` is trivially true, and `(>= ts prev)` holds because `ts` is the first/only future value seen.
3. `price-resolve` executes `(map-set last-update key timestamp)` because `timestamp > last-update-time`, permanently recording the future `ts` as the asset's `last-update` value.
4. Any subsequent, legitimately-timestamped price resolution for asset `X` by any other user has `ts' < prev` (the poisoned future value), failing `(>= ts' prev)` in `oracle-timestamp-fresh`, causing `ERR-ORACLE-INVARIANT` for every borrow/withdraw/liquidation call that needs asset `X`'s price, until `stacks-block-time` advances past the poisoned `prev` value.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L365-371)
```text
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L373-395)
```text
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
