### No vulnerability found for this question.

**Reasoning:** The `relevant` filter in `iter-lookup-collateral` (mainnet/contracts/market/v0-market-vault.clar:180) excludes disabled assets from the position returned to `liquidate`, which is exactly the "liquidation of disabled collateral" behavior the rules explicitly designate as an out-of-scope, deliberate safety design decision [1](#0-0) .

More importantly, the claimed exploit mechanism ("route a victim's mandatory payout through a principal that always rejects delivery") doesn't map onto real code behavior here. In `liquidate`, the `collateral-receiver` is an optional parameter supplied by the caller (the liquidator, i.e., attacker A) themselves, defaulting to the liquidator if unset: `(actual-receiver (match collateral-receiver recv recv liquidator))` [2](#0-1) . This only determines where A's own seized collateral reward is sent — A is choosing the destination for A's own inbound funds, not forcing B's (the borrower/victim's) payout through a hostile principal. There is no code path where B is compelled to send funds to a receiver chosen by A; B's collateral is debited from B's position and credited to whichever address A specifies for A's own liquidation reward, which is standard liquidator-controlled routing, not theft of B's funds.

The rules require two distinct unprivileged principals where B suffers a loss from a shared-state bug written by A and read by B. Here the only "victim" of the disabled-asset exclusion is the borrower's own excluded collateral not being counted toward their own health/liquidation math — a self-affecting design behavior explicitly excluded by the rules — and the `collateral-receiver` mechanism only affects where the caller's own reward goes, not a forced payout of another user's funds through a rejecting contract.

### Citations

**File:** mainnet/contracts/market/v0-market-vault.clar (L175-196)
```text
(define-private (relevant (asset uint) (enabled-mask uint) (c bool))
  (let ((position (mask-pos asset c))
        (mask (bit-or u0 (pow u2 position))))
    (subset mask enabled-mask)))

(define-private (iter-lookup-collateral
                (asset uint)
                (acc {
                    id: uint,
                    result: (list 64 { aid: uint, amount: uint}),
                    enabled-mask: uint
                }))
  (let ((mask (get enabled-mask acc))
        (relevant? (asserts! (relevant asset mask true) acc))
        (user-id (get id acc))
        (value (get-collateral user-id asset))
        (entry { aid: asset, amount: value }))
    {
      id: user-id,
      result: (unwrap-panic (as-max-len? (append (get result acc) entry) u64)),
      enabled-mask: mask
    }))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1504-1512)
```text
          ;; Collateral receiver defaults to liquidator if not specified
          (actual-receiver (match collateral-receiver recv recv liquidator))
          (coll-removed (try! (contract-call? .v0-market-vault
                              collateral-remove
                              borrower
                              coll-final
                              collateral-ft
                              coll-aid
                              actual-receiver)))
```
