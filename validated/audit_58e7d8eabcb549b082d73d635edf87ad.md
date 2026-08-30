## Title
Future-dated oracle price update poisons the shared `last-update` cache and permanently blocks legitimate price refreshes for every user of that feed - (File: mainnet/contracts/market/v0-4-market.clar)

## Summary
`oracle-timestamp-fresh` in the market contract treats any price whose timestamp is *ahead* of the current chain time as automatically "fresh" (`delta = 0`), and the caller-supplied timestamp is then written into the global `last-update` map that is shared by **every** account that ever needs a price for that oracle feed. Because the map is keyed only by `{ type, ident }` (i.e. per price feed, not per caller or per position), one account's price submission can poison the monotonic-timestamp guard for all other, unrelated market participants who depend on the same feed.

## Finding Description
`last-update` is a single shared map, not scoped to the submitting account: [1](#0-0) 

The freshness check computes the staleness delta in a way that silently zeroes it out whenever the supplied timestamp is greater than the current block time: [2](#0-1) 

`price-resolve` accepts the price as long as `delta <= max-staleness` (trivially true when `delta == 0`) **and** `ts >= prev`, then unconditionally advances the shared `last-update` entry to the new (attacker/erroneously future-dated) timestamp: [3](#0-2) 

Once `last-update[{type, ident}]` has been advanced to a future value `T_future`, every subsequent, correctly-timestamped price update for the same feed (submitted by any other, unrelated account) will have `ts_real < T_future`, so the `(>= ts prev)` check fails and `price-resolve` returns `ERR-ORACLE-INVARIANT` for that feed until real chain time catches up to `T_future`. This is the same class of bug as the report's prototype-pollution: a single unprivileged write mutates a **shared object** (`last-update`) that many independent principals subsequently read/rely on, and there is no isolation between the caller who wrote it and the victims who read it.

Any market action that needs to price an asset served by this feed will call `price-resolve`/`price-multi-resolve` and therefore revert while the feed is "poisoned":
- `borrow`, `collateral-add` (health checks) 
- `liquidate` / `liquidate-multi` (an unhealthy borrower cannot be liquidated) [4](#0-3) 

Because `liquidate` also depends on this same price resolution path, an attacker (or even an honest user who happens to relay a Pyth/DIA update whose embedded publish-time is ahead of the Stacks block's `stacks-block-time`, e.g. due to normal clock skew between the oracle network and the chain) can lock out liquidations for every position that uses that collateral/debt asset, for as long as the poisoned future timestamp remains ahead of real chain time. This is a bug in *this* contract's timestamp-validation logic (accepting `ts > now` as "fresh" and using it to overwrite shared global state), not a case of "incorrect data supplied by third-party oracles" being blindly trusted for its price value — the price itself may be fine; it is the code's mishandling of the shared `last-update` cache that causes harm to unrelated third parties.

## Impact Explanation
While the feed is poisoned, borrowers who should be liquidated (e.g., during a price crash) cannot be liquidated because `liquidate` reverts with `ERR-ORACLE-INVARIANT`, exposing suppliers/lenders to additional bad debt that would otherwise have been captured by timely liquidation. Ordinary users' `borrow`/`collateral-add` calls for that asset also revert. This is a temporary freezing of protocol functionality (and by extension of unclaimed yield/collateral that cannot be liquidated in time), affecting parties other than whoever submitted the poisoning update — satisfying the "temporary freezing of funds" impact class.

## Likelihood Explanation
The write path is reachable by any unprivileged account via the normal `price-feeds` parameter accepted by `borrow`/`collateral-add`/`liquidate` (`write-feeds` → `write-feed` → `price-resolve`), requiring no privileged role. It only requires a validly-signed Pyth/DIA update whose embedded timestamp is ≥ current `stacks-block-time` — plausible from ordinary oracle/chain clock skew, and trivially reproducible by a user who withholds and later submits a marginally "future" (relative to a lagging block) but genuinely signed update.

## Recommendation
Reject prices whose timestamp is in the future relative to `stacks-block-time` (or bound the allowed forward skew tightly) instead of setting `delta = 0`; and/or scope `last-update` staleness/monotonicity enforcement more defensively so a single erroneous or malicious future timestamp cannot permanently block all subsequent legitimate updates for the shared feed until real time catches up.

## Proof of Concept
1. Attacker (or any user) calls `borrow`/`collateral-add` with `price-feeds` containing a validly Pyth-signed update for feed `F` whose `publish-time` is `T_future > stacks-block-time` (achievable via normal oracle/chain clock skew or by holding a slightly-ahead update).
2. `oracle-timestamp-fresh` computes `delta = 0` (since `ts > stacks-block-time`), passing the staleness check; `price-resolve` stores `last-update[F] = T_future`.
3. Any other user (e.g., a borrower who needs to be liquidated) submits a fresh, correctly-timed Pyth update for `F` with `ts_real < T_future`.
4. `oracle-timestamp-fresh` now fails `(>= ts prev)`, causing `price-resolve` / `price-multi-resolve` to return `ERR-ORACLE-INVARIANT`, which reverts `liquidate`, `borrow`, and `collateral-add` for every account exposed to asset `F` until `stacks-block-time` exceeds `T_future`.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L117-120)
```text
;; -- Oracle timestamp tracking
(define-map last-update
  { type: (buff 1), ident: (buff 32) }
  uint)
```

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1382-1410)
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

    (coll-address (contract-of collateral-ft))
    (debt-address (contract-of debt-ft))
    (coll-asset (try! (get-asset coll-address)))
    (debt-asset (try! (get-asset debt-address)))
    (coll-aid (get id coll-asset))
    (debt-aid (get id debt-asset))

    ;; accrue FIRST - populates cache for zToken price resolution
    (u-debt (accrue-user-debts (get debt pos-full)))
    (u-coll (accrue-user-collateral (get collateral pos-full)))

    ;; NOW safe to resolve prices (cache is populated)
    (assets (get-assets mask))
```
