### No vulnerability found for this question.

`collateral-remove-redeem` and the `collateral-remove` function it calls both hard-code `(account contract-caller)` [1](#0-0)  and [2](#0-1) , meaning the caller can only remove and redeem collateral from their own position — there is no `on-behalf-of` or account parameter that lets a caller act on another principal's position. `convert-to-scaled-debt` itself is a simple index-scaling helper with no list/fold operation that could be pushed "past a fold bound" [3](#0-2) , and it is only reachable from `borrow`/`repay`-style debt paths operating on the account's own position, not from a third party's position via `collateral-remove-redeem`. Since the rules require two distinct unprivileged principals where B's position/state is affected by A's transaction, and no such cross-account write/read path exists here, this claim does not describe an actual vulnerability in this code.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L648-652)
```text
(define-private (convert-to-scaled-debt (asset-id uint) (amount uint) (round-up bool))
  (let ((borrow-index (get index (unwrap-panic (get-cached-indexes asset-id)))))
  (if round-up
    (mul-div-up amount INDEX-PRECISION borrow-index)
    (mul-div-down amount INDEX-PRECISION borrow-index))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1107-1114)
```text
(define-public (collateral-remove (ft <ft-trait>) (amount uint) (receiver (optional principal)) (price-feeds (optional (list 3 (buff 8192)))))
  (let ((ft-address (contract-of ft))
        (asset (try! (get-asset ft-address)))
        (asset-id (get id asset))
        (account contract-caller)
        (collateral-receiver (match receiver recv recv contract-caller))
        (position (try! (get-position account)))
        (has-debt (> (len (get debt position)) u0)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1211-1228)
```text
(define-public (collateral-remove-redeem (ft <ft-trait>) (amount uint) (min-underlying uint) (receiver (optional principal)) (price-feeds (optional (list 3 (buff 8192)))))
  (let ((ft-address (contract-of ft))
        (asset (try! (get-asset ft-address)))
        (ztoken-id (get id asset))
        (underlying-id (if (is-eq ztoken-id zSTX) STX
                       (if (is-eq ztoken-id zsBTC) sBTC
                       (if (is-eq ztoken-id zstSTX) stSTX
                       (if (is-eq ztoken-id zUSDC) USDC
                       (if (is-eq ztoken-id zUSDH) USDH
                       (if (is-eq ztoken-id zstSTXbtc) stSTXbtc
                       u100)))))))  ;; invalid sentinel for non-ztoken
        (funds-receiver (match receiver recv recv contract-caller)))

    (asserts! (<= underlying-id stSTXbtc) ERR-UNKNOWN-VAULT)
    
    ;; Step 1: Remove collateral - sends zTokens to THIS contract (market)
    ;; receiver=current-contract so market holds the zTokens
    (try! (collateral-remove ft amount (some current-contract) price-feeds))
```
