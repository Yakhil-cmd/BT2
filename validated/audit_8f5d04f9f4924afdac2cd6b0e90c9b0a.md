## Title
Future-timestamped price updates bypass staleness checks and permanently poison the shared `last-update` oracle floor, freezing price resolution for all market participants - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
The market's oracle freshness check, `oracle-timestamp-fresh`, treats any price whose reported timestamp is *greater* than the current `stacks-block-time` as automatically fresh (`delta` is forced to `u0`), instead of rejecting or bounding it. That un-vetted timestamp is then written into the market-wide, per-feed `last-update` map, which enforces a strictly monotonic floor (`>= ts prev`) for every future price resolution of that asset. Because this map is keyed only by `{type, ident}` (i.e., shared by the entire market, not per-caller), any single unprivileged transaction that relays a Pyth/DIA update whose publish-time outruns the Stacks block's timestamp permanently raises the floor for every other user, borrower, and liquidator relying on that asset's price - until real-world/oracle time catches up.

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

When a supplied price timestamp `ts` is ahead of the current block's `stacks-block-time`, `delta` is forced to `0`, so the `<= delta max-staleness` check always passes regardless of how far in the future `ts` is. There is no upper bound anywhere else in the pipeline: neither `resolve-pyth`/`resolve-dia` [2](#0-1)  nor the underlying `pyth-storage-v4.write-batch-entry` [3](#0-2)  validate that `publish-time` is not ahead of chain time - both only check a *lower* staleness bound.

`price-resolve` then persists this timestamp into the shared, market-wide `last-update` map whenever it exceeds the previously stored value: [4](#0-3) 

```clarity
(define-private (price-resolve
  (data { type: (buff 1), ident: (buff 32), callcode: (optional (buff 1)), max-staleness: uint }))
  ...
  (asserts! (and (oracle-price-legal final-price) (oracle-timestamp-fresh timestamp last-update-time max-staleness))
            ERR-ORACLE-INVARIANT)
  ;; update timestamp if newer
  (if (> timestamp last-update-time)
      (map-set last-update key timestamp)
      false)
  (ok final-price)))
```

`last-update` is declared once per asset identifier, not per account or per transaction: [5](#0-4) 

Because the floor is keyed only by `{type, ident}`, it is the *shared state* consumed by every subsequent caller who needs a price for that identifier - borrowers, depositors, liquidators, and health checks alike - satisfying the "shared cache/index primed by one caller, consumed by another" analog to the reported CVE class (state primed by one party silently blocks/harms unrelated later parties).

### Impact Explanation
Attacker: any unprivileged account calling any public entry point that accepts `price-feeds` (e.g. `borrow`, `collateral-add`, `liquidate`) with a validly-signed Pyth/DIA update whose `publish-time` is ahead of the Stacks block's `stacks-block-time` (achievable naturally from oracle/chain clock skew, or deliberately by choosing the most recent available signed update when block production lags real time). This single transaction pushes `last-update-` for that asset to the future timestamp.

Victim: every other market participant (any account with collateral/debt in that asset) whose subsequent transaction needs a price for the same identifier. Once the floor is poisoned, `(>= ts prev)` fails for any legitimately-timestamped subsequent update until on-chain/oracle time actually reaches the poisoned value, causing `ERR-ORACLE-INVARIANT` on borrow, repay, liquidate, collateral-add/remove, and health checks that touch that asset.

Outcome with attacker's tx vs. without: without it, all users can resolve fresh prices normally each block; with it, all users are denied price resolution for that asset (temporary freeze of borrow/repay/liquidate/withdraw flows depending on it) for as long as the poisoned floor remains ahead of real time - potentially compounding if the attacker keeps re-poisoning it further into the future. This is a temporary freezing of funds/operations affecting third parties, landing in the in-scope **High** impact bucket.

### Likelihood Explanation
The only precondition is submitting a validly-signed Pyth/DIA payload whose publish-time is not behind the Stacks block time it lands in - something any user relaying the "latest" available signed price update can trigger without any privileged access, and which can also occur incidentally from normal oracle/chain clock skew. No governance, DAO, or oracle-source compromise is required; the flaw is in `oracle-timestamp-fresh`'s own future-timestamp handling.

### Recommendation
Reject (rather than auto-pass) timestamps that exceed `stacks-block-time` by more than a small allowed tolerance, e.g.:
```clarity
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (and
    (<= ts (+ stacks-block-time MAX-FUTURE-DRIFT))
    (<= (if (> ts stacks-block-time) u0 (- stacks-block-time ts)) max-staleness)
    (>= ts prev)))
```
and only advance `last-update-` after this stricter check succeeds, so a single caller cannot ratchet the shared monotonic floor beyond real time.

### Proof of Concept
1. Attacker fetches a genuinely Pyth-signed VAA for asset `X` whose `publish-time` is, e.g., 1 hour ahead of the current Stacks block's `stacks-block-time` (this can occur from natural relay/clock skew, or by waiting for/selecting such an update).
2. Attacker calls any public function accepting `price-feeds` (e.g. `collateral-add`) supplying this VAA; `write-feeds` → `pyth-storage-v4.write` succeeds since only a lower staleness bound is enforced.
3. `price-resolve` calls `oracle-timestamp-fresh` with `ts` = future publish-time; since `ts > stacks-block-time`, `delta = 0`, check passes; `last-update-` for `{TYPE-PYTH, X}` is set to the future timestamp.
4. Any other user (or the same market for a different account) subsequently calling `borrow`/`liquidate`/etc. for asset `X` with a legitimately fresh (real-time) Pyth update now fails `(>= ts prev)` in `oracle-timestamp-fresh` because `prev` is the poisoned future value, reverting with `ERR-ORACLE-INVARIANT` until real/oracle time reaches the poisoned timestamp. [6](#0-5)

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L117-119)
```text
;; -- Oracle timestamp tracking
(define-map last-update
  { type: (buff 1), ident: (buff 32) }
```

**File:** mainnet/contracts/market/v0-4-market.clar (L322-330)
```text
(define-private (call-dia (key (string-ascii 32)))
  (let ((res (unwrap! (contract-call? 'SP1G48FZ4Y7JY8G2Z0N51QTCYGBQ6F4J43J77BQC0.dia-oracle get-value key) ERR-ORACLE-DIA)))
    (ok res)))

(define-private (resolve-dia (ident (buff 32)))
  (let ((key (unwrap-panic (from-consensus-buff? (string-ascii 32) ident)))
        (res (try! (call-dia key))))
    ;; DIA returns timestamp in milliseconds, convert to seconds for staleness check
    (ok { value: (get value res), timestamp: (/ (get timestamp res) u1000) })))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L365-395)
```text
(define-private (oracle-timestamp-fresh (ts uint) (prev uint) (max-staleness uint))
  (let ((delta (if (> ts stacks-block-time)
                   u0
                   (- stacks-block-time ts))))
    (and
      (<= delta max-staleness)
      (>= ts prev))))

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

**File:** local-testing/contracts/pyth/contracts/pyth-storage-v4.clar (L74-91)
```text
(define-private (write-batch-entry (entry {
		price-identifier: (buff 32),
		price: int,
		conf: uint,
		expo: int,
		ema-price: int,
		ema-conf: uint,
		publish-time: uint,
		prev-publish-time: uint,
	}))
	(let ((stale-price-threshold (contract-call? .pyth-governance-v3 get-stale-price-threshold))
			(latest-stacks-timestamp (unwrap! (get-stacks-block-info? time (- stacks-block-height u1)) ERR_STALE_PRICE))
			(publish-time (get publish-time entry)))
		;; Ensure that we have not processed a newer price
		(asserts! (is-price-update-more-recent (get price-identifier entry) publish-time) ERR_NEWER_PRICE_AVAILABLE)
		;; Ensure that price is not stale
		(asserts! (>= publish-time (+ (- latest-stacks-timestamp stale-price-threshold) STACKS_BLOCK_TIME)) ERR_STALE_PRICE)
		;; Update storage
```
