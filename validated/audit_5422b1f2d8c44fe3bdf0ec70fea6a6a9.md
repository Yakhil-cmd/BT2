### No vulnerability found for this question.

`call-ststx-ratio` is a public function that simply proxies a read from an external contract and returns the ratio value; it takes no account parameter and writes no state, ledger, or position data anywhere. [1](#0-0) 

It does not call `resolve-price-feed` at all — that dispatch happens only inside `price-resolve`, which is invoked from position/collateral operations (e.g. `collateral-add`) where `contract-caller` must equal `tx-sender`, and which only affects the caller's own accrued state via `write-feeds`/`get-notional-evaluation`. [2](#0-1) [3](#0-2) 

There is no code path where an unprivileged caller of `call-ststx-ratio` writes to another principal's ledger, position, or balance "on-behalf-of" them — no account/recipient argument exists in this function, and no shared victim state is touched. The premise of the question (that `call-ststx-ratio` reaches `resolve-price-feed` and performs an unsolicited write to a stranger's ledger) does not match the actual code.

### Citations

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1014-1016)
```text
;; ststx ratio transformation
(define-public (call-ststx-ratio)
  (contract-call? 'SP4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7DVMDPBG.block-info-nakamoto-ststx-ratio-v2 get-ststx-ratio-v3))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1020-1030)
```text
(define-public (collateral-add (ft <ft-trait>) (amount uint) (price-feeds (optional (list 3 (buff 8192)))))
  (let ((ft-address (contract-of ft))
        (asset (try! (get-asset ft-address)))
        (asset-id (get id asset))
        (account contract-caller))

    (asserts! (get collateral asset) ERR-COLLATERAL-DISABLED)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    ;; Validate future mask has valid egroup AND check health if user has debt
    
    (match (contract-call? .v0-market-vault resolve-safe account)
```
