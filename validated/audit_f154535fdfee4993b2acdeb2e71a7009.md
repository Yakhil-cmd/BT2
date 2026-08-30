[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1020-1035)
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
      user-registry-data
        ;; User has existing position - check if adding NEW collateral asset
        (let ((current-raw-mask (get mask user-registry-data))
              (future-raw-mask (bit-or current-raw-mask (pow u2 asset-id)))
              (is-new-collateral (not (is-eq future-raw-mask current-raw-mask))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1145-1153)
```text
                (let ((oracle-data (get oracle asset))
                      (price (unwrap! (price-resolve oracle-data) ERR-DISABLED-COLLATERAL-PRICE-FAILED))
                      (decimals (get decimals asset))
                      (user-amount (find-collateral-amount (get collateral pos-full) asset-id))
                      (disabled-notional (normalize (* user-amount price) decimals false))
                      (removal-notional (normalize (* amount price) decimals true))
                      (total-collateral-value (+ collateral-value disabled-notional)))
                  (asserts! (>= total-collateral-value removal-notional) ERR-INSUFFICIENT-COLLATERAL)
                  (is-healthy (- total-collateral-value removal-notional) debt-value current-ltvb)))
```
