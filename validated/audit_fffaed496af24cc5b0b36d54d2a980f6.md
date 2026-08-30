### No vulnerability found for this question.

`oracle-last-update` (mainnet/contracts/market/v0-4-market.clar:939) is a plain read-only accessor to the `last-update` map and performs no mutation. [1](#0-0) 

The only path that mutates `last-update` is `price-resolve`, invoked (via `write-feeds`) from `borrow`, and it only updates the timestamp for a feed key when a **cryptographically-verified, monotonically newer** Pyth price update is supplied (`verify-and-update-price-feeds` against `pyth-storage-v4`/`pyth-pnau-decoder-v3`/`wormhole-core-v4`, plus `oracle-timestamp-fresh` enforcing `ts >= prev`). [2](#0-1) [3](#0-2) 

An attacker cannot forge a favorable price since Pyth/Wormhole signature verification is required, and any legitimate fresh update from a real Pyth attestation is a genuine market price change that necessarily affects every holder of assets sharing that `{type, ident}` feed identically — this is the explicitly out-of-scope case of "a price move affecting everyone." There is no mechanism here by which attacker A's `borrow` call can inject an incorrect/self-serving price to disadvantage a specific victim B beyond what a real oracle update would do; `oracle-timestamp-fresh` and Pyth/Wormhole verification prevent stale or forged data, and choosing the `ft` trait principal only selects which asset's feed is written, not the price content, which comes from signed off-chain data. This is normal oracle mechanics, not a defect in this code.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L126-152)
```text
;; -- Price feed update helpers ----------------------------------------------

;; Write a single Pyth price feed update using fold accumulator pattern
(define-private (write-feed (feed (buff 8192)) (status (response bool uint)))
  (match status
    success-status
      (match (contract-call? 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-oracle-v4 verify-and-update-price-feeds
          feed
          {
            pyth-storage-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-storage-v4,
            pyth-decoder-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-pnau-decoder-v3,
            wormhole-core-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.wormhole-core-v4,
          }
        )
        update-success (ok true)
        update-failed ERR-PRICE-FEED-UPDATE-FAILED)
    error-status status
  )
)

;; Process optional list of price feed updates
;; If list is provided, folds over it and updates all feeds
;; If list is none, does nothing (allows for backward compatibility)
(define-private (write-feeds (feeds (optional (list 3 (buff 8192)))))
  (match feeds
    entries (fold write-feed entries (ok true))
    (ok true)))
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

**File:** mainnet/contracts/market/v0-4-market.clar (L939-940)
```text
(define-read-only (oracle-last-update (f {type: (buff 1), ident: (buff 32)}))
  (default-to u0 (map-get? last-update f)))
```
