### No vulnerability found for this question.

`resolve-dia` and `price-resolve` update a global `last-update` map keyed by `{type, ident}` (the price feed identity), but this update is monotonic and gated: it only records a **newer** timestamp obtained from a legitimate oracle call, and `oracle-timestamp-fresh` rejects any timestamp older than the previous one [1](#0-0) . An unprivileged caller of `borrow` cannot inject an arbitrary or stale price into this shared cache — the value comes directly from the external Pyth/DIA oracle contract call, not attacker-supplied data [2](#0-1) . Refreshing this cache to a newer, oracle-validated timestamp only makes subsequent reads in the same block use fresher (not manipulated) prices — this benefits correctness for all users reading the same feed, it does not let attacker A devalue or reprice victim B's collateral to B's detriment.

Within `borrow`, the accrual steps (`accrue-user-debts`, `accrue-user-collateral`, `accrue-and-cache`) only touch the caller's own position and the shared vault liquidity index update, which is the standard interest-accrual mechanism common to all lending positions using that vault [3](#0-2) . This accrual just brings the index up to date to the current block timestamp; it does not create attacker-controlled mispricing of other holders' collateral. There is no code path shown where reordering "accrual vs. price resolution" inside the `let` in `borrow` allows A to profit at B's expense within the same transaction — the shared state A can influence (index caches, last-update timestamps) can only move toward correctness, not toward an exploitable stale or manipulated value for another account's position.

Since the required two-principal (attacker A, victim B) loss cannot be demonstrated from the actual code — the shared state writes here are monotonic, oracle-validated, and beneficial rather than adversarial — this does not meet the bar for a valid, in-scope finding.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L308-330)
```text
(define-private (call-pyth (ident (buff 32)))
  (let ((res (unwrap! (contract-call? 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-storage-v4 get-price ident) ERR-ORACLE-PYTH)))
    (ok res)))

(define-private (resolve-pyth (ident (buff 32)))
  (let ((response (try! (call-pyth ident)))
        (price (get price response))
        (expo (get expo response))
        (conf (get conf response))
        (final-price (normalize-pyth price expo))
        (timestamp (get publish-time response)))
    (try! (check-confidence price conf))
    (ok { value: final-price, timestamp: timestamp })))

(define-private (call-dia (key (string-ascii 32)))
  (let ((res (unwrap! (contract-call? 'SP1G48FZ4Y7JY8G2Z0N51QTCYGBQ6F4J43J77BQC0.dia-oracle get-value key) ERR-ORACLE-DIA)))
    (ok res)))

(define-private (resolve-dia (ident (buff 32)))
  (let ((key (unwrap-panic (from-consensus-buff? (string-ascii 32) ident)))
        (res (try! (call-dia key))))
    ;; DIA returns timestamp in milliseconds, convert to seconds for staleness check
    (ok { value: (get value res), timestamp: (/ (get timestamp res) u1000) })))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L365-393)
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
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1246-1258)
```text
        ;; Step 1: Get position WITHOUT resolving prices
        (position (try! (get-position account)))
        (mask (get mask position))
        
        ;; Step 2: Accrue user's positions (populates cache for ztokens)
        (u-debt (accrue-user-debts (get debt position)))
        (u-coll (accrue-user-collateral (get collateral position)))
        
        ;; Step 3: Accrue the asset being borrowed (needed for index access)
        (unused (accrue-and-cache asset-id))
        
        ;; Step 4: NOW safe to resolve prices (cache is populated)
        (assets (get-assets mask))
```
