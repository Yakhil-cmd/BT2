[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** mainnet/contracts/market/v0-market-vault.clar (L68-77)
```text
(define-map registry
            uint
            {
              id: uint,
              account: principal,
              mask: uint,
              last-update: uint,
              last-borrow-block: uint,
            })
(define-map reverse principal uint)
```

**File:** mainnet/contracts/market/v0-market-vault.clar (L171-171)
```text
(define-private (refresh (mask uint)) { mask: mask, last-update: stacks-block-time })
```

**File:** mainnet/contracts/market/v0-market-vault.clar (L442-450)
```text
(define-public (debt-add-scaled (account principal) (scaled-amount uint) (asset-id uint))
  (let ((states (var-get pause-states))
        (entry (resolve-or-create account))
        (user-id (get id entry))
        (mask (get mask entry))
        (update-mask (mask-update mask asset-id false true)) ;; debt, insert
        ;; Oracle frontrunning protection: record current block when borrowing
        (updated-entry (merge entry { mask: update-mask, last-update: stacks-block-time, last-borrow-block: stacks-block-height }))
        (result (add-user-scaled-debt user-id asset-id scaled-amount)))
```

**File:** mainnet/contracts/market/v0-market-vault.clar (L473-488)
```text
(define-public (debt-remove-scaled (account principal) (scaled-amount uint) (asset-id uint))
  (let ((states (var-get pause-states))
        (entry (resolve account))
        (user-id (get id entry))
        (mask (get mask entry))
        (remaining (try! (remove-user-scaled-debt user-id asset-id scaled-amount)))
        (nmask (if (is-eq remaining u0)
                      (mask-update mask asset-id false false) ;; debt, remove
                      mask))
        (updated-entry (merge entry (refresh nmask))))

    (try! (check-impl-auth))
    (asserts! (not (get debt-remove states)) ERR-PAUSED)
    (asserts! (> scaled-amount u0) ERR-AMOUNT-ZERO)

    (insert updated-entry)
```
