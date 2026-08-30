## Analysis

The reported bug class ("no way to recover once oracle state is poisoned, DOSing all users") maps to `oracle-timestamp-fresh` / `price-resolve` in `mainnet/contracts/market/v0-4-market.clar`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Future-dated oracle timestamp permanently poisons the shared `last-update` map, freezing price resolution for all users of an asset - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
`oracle-timestamp-fresh` treats any price timestamp greater than `stacks-block-time` as automatically "fresh" (`delta` forced to `u0`), bypassing the staleness bound entirely. `price-resolve` then unconditionally writes that timestamp into the global, per-feed `last-update` map whenever it exceeds the previously stored value. Because every future call to `price-resolve` for that same `{type, ident}` feed enforces `(>= ts prev)`, once an inflated timestamp is recorded, no subsequent (correctly-timed) price update can pass the monotonic check until real/block time actually reaches that stored value. There is no DAO or public function to reset `last-update` for a feed.

### Finding Description
`price-resolve` resolves the price for a given oracle feed and validates it:

```
(asserts! (and (oracle-price-legal final-price) (oracle-timestamp-fresh timestamp last-update-time max-staleness))
          ERR-ORACLE-INVARIANT)
(if (> timestamp last-update-time)
    (map-set last-update key timestamp)
    false)
``` [4](#0-3) 

`last-update` is a single global map keyed only by `{type, ident}` (the price feed identifier), shared across every asset that references that feed (e.g. the same Pyth STX/USD feed backs `STX`, `stSTX`, `zSTX`, `zstSTX`) and across every user who ever interacts with those assets:

```
(define-map last-update
  { type: (buff 1), ident: (buff 32) }
  uint)
``` [3](#0-2) 

`oracle-timestamp-fresh` is supposed to bound how far the price can be from the current block time, but for any timestamp ahead of `stacks-block-time` it silently forces `delta` to `0`, which always satisfies `<= delta max-staleness`:

```
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))
``` [1](#0-0) 

Any unprivileged caller can attach a valid, signed Pyth price update via the `price-feeds` parameter of `borrow`, `repay`, `withdraw`, etc., which is forwarded to `write-feeds`/`write-feed` and stored in `pyth-storage-v4` before market reads it. Because Stacks block timestamps can legitimately lag real (Pyth publisher) time, a valid Pyth VAA whose `publish-time` is ahead of the current `stacks-block-time` will always be accepted as "fresh" regardless of how far ahead it is, and will overwrite `last-update` with that inflated value. Once this occurs, `oracle-timestamp-fresh`'s second condition `(>= ts prev)` blocks every subsequent price for that feed until the chain's `stacks-block-time` catches up to the poisoned value — and there is no DAO/administrative function anywhere in the contract to clear or reset an entry in `last-update`.

### Impact Explanation
While the poisoned `last-update` entry is in effect, every user (not just the caller who submitted the update) who needs to resolve that feed's price — for borrowing, health checks, collateral withdrawal, or liquidation of any asset that shares that feed/identifier — has their transactions revert with `ERR-ORACLE-INVARIANT`. This is a freezing-of-funds condition affecting all unrelated market participants exposed to that asset, imposed by one unprivileged caller's transaction, with no recovery mechanism available to governance. This lands on the in-scope Impact class of **temporary freezing of funds** (recoverable once wall/block time passes the poisoned timestamp) and can approach **permanent freezing** if the inflated timestamp is large enough relative to `max-staleness` and block cadence.

### Likelihood Explanation
The precondition — a Pyth `publish-time` momentarily ahead of the Stacks `stacks-block-time` — is a routine occurrence given normal clock/block-production drift and does not require any signature forgery, only submission of a legitimately-signed, currently valid Pyth VAA via the existing `price-feeds` parameter that any address can already pass into public entrypoints such as `borrow`. No special privileges are required to trigger it.

### Recommendation
Do not special-case timestamps that are ahead of `stacks-block-time` to `delta = 0`; instead reject or clamp future timestamps (e.g. treat `ts > stacks-block-time` as invalid, or bound the allowed forward skew), and/or provide a DAO-gated function to reset a poisoned `last-update` entry so price resolution for an asset can be recovered without waiting for block time to overtake an inflated value.

### Proof of Concept
1. Any user calls `borrow` (or another entrypoint accepting `price-feeds`) supplying a currently valid Pyth VAA for feed `F` whose `publish-time` is a few seconds/minutes ahead of the current `stacks-block-time` (a normal occurrence, not an attack on Pyth itself).
2. `price-resolve` calls `oracle-timestamp-fresh(timestamp, last-update-time, max-staleness)`; since `timestamp > stacks-block-time`, `delta` is forced to `0`, the freshness check passes trivially, and `map-set last-update key timestamp` stores the inflated timestamp.
3. Any other user later calls `borrow`/`repay`/`withdraw`/`liquidate` involving an asset backed by feed `F` with a legitimately-timed, correct Pyth update (`ts` less than the poisoned value); `oracle-timestamp-fresh` returns `false` because `(>= ts prev)` fails, causing `price-resolve` to return `ERR-ORACLE-INVARIANT` and the whole transaction to revert.
4. This denial persists for all users of assets tied to feed `F` until real/block time surpasses the poisoned stored timestamp; there is no DAO function to clear `last-update`.

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
