## Title
Unchecked inner `bool` on sBTC `transfer` calls lets `try!` treat `(ok false)` as success, silently double-counting/losing custodied sBTC - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`pox-5.clar` moves sBTC by calling `(contract-call? 'SM3...sbtc-token transfer ...)` and wrapping the result in `try!` in several places: `roll-sbtc`, `unstake-sbtc`, `transfer-from-reserve`, and `transfer-stranded-rewards`. `try!` only short-circuits on an `(err ...)` response; a SIP-010 `transfer` implementation that returns `(ok false)` instead of an `err` on failure (analogous to ERC-20 tokens that return `false` rather than reverting, which is exactly the bug class flagged in the external report) is silently accepted as a success by `try!`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
In each of these functions, pox-5 first mutates its own internal accounting state (`total-sbtc-staked`, `reserve-balance`, `protocol-bonds-total-staked`, etc.) and only afterward calls the external sBTC token's `transfer` function, using `try!` to propagate failure:

- `unstake-sbtc`: decrements `total-sbtc-staked` and per-bond staked totals, *then* calls `transfer` to actually pay the staker back [5](#0-4) .
- `roll-sbtc`: adjusts `total-sbtc-staked` up or down based on the delta, and calls `transfer` for the delta (pulling from staker or refunding staker) [6](#0-5) .
- `transfer-from-reserve`: decrements `reserve-balance` by `amount`, then calls `transfer` to actually move the sats out [7](#0-6) .
- `transfer-stranded-rewards`: calls `transfer` directly with no internal balance accounting at all (this one relies purely on the transfer's honesty) [4](#0-3) .

Because `try!` unwraps a `(response bool uint)` and only errors on the `err` branch, if the token's `transfer` returns `(ok false)` — a value indicating the underlying `ft-transfer?` did not actually move the balance (see the SIP-010 `ft-transfer?` documented failure codes, `(err u1)`/`(err u2)`/`(err u3)`, which a wrapper contract could choose to convert to `(ok false)` instead of propagating as an `err`) — pox-5 proceeds as if the transfer succeeded. This exact bug class (checking only that a call didn't revert/err, not that its inner success flag is `true`) is the direct analog of the ERC-20 `transfer`/`transferFrom` return-value issue in the external report: some tokens signal failure via a return value rather than via revert/error, and code that doesn't check that value can become desynchronized from actual token balances.

### Impact Explanation
If the canonical sBTC token contract (or any contract substituted at its address in test/alternate configurations) were to return `(ok false)` on a failed transfer instead of an `err`, pox-5's internal ledger (`total-sbtc-staked`, `reserve-balance`, per-bond staked totals) would already have been decremented/adjusted as though sats moved, while the staker's/recipient's actual sBTC balance would remain unchanged. This breaks the core equality that `total-sbtc-staked` (and reserve accounting) must equal the sBTC the contract actually custodies:
- In `unstake-sbtc`, the staker's stake is marked unstaked and cycle totals reduced, but the staker never actually receives their sats back — a permanent freeze of the staker's sBTC.
- In `roll-sbtc`, the "refund" branch could silently fail to return sats to the staker while `total-sbtc-staked` is decremented, again freezing funds while under-reporting how much sBTC the contract still (falsely) claims is unaccounted for/available.
- In `transfer-from-reserve` and `transfer-stranded-rewards`, `reserve-balance` (or the intended payout) could be decremented/considered paid while the recipient receives nothing, permanently losing/freezing that value inside the contract with no on-chain record that it's still owed.

This matches the Critical/High categories: permanent freezing of staked sBTC, and double counting/desynchronization of a reserve or committed balance.

### Likelihood Explanation
This is not exploitable against the actual canonical `sbtc-token` contract as deployed by the sBTC protocol, if that contract's `transfer` faithfully wraps `ft-transfer?` and always returns the same error path on failure (never converting a failure into `(ok false)`), so the practical likelihood on mainnet against the real sBTC token is currently unproven. However, the finding is a real gap in the contract logic and defense-in-depth: `pox-5.clar` does not itself unwrap and assert the inner boolean of the `transfer` response as `true` at any of the four call sites; it relies entirely on the good behavior of the sBTC token, exactly the class of assumption the external SafeERC20 report warns against.

### Recommendation
At every sBTC (and any other externally-defined SIP-010 token) `transfer` call site in `pox-5.clar` (`roll-sbtc`, `unstake-sbtc`, `transfer-from-reserve`, `transfer-stranded-rewards`), replace the bare `(try! (contract-call? ... transfer ...))` pattern with an explicit check that the inner boolean is `true`, e.g. `(asserts! (try! (contract-call? ... transfer ...)) ERR_TRANSFER_FAILED)`, so a `(ok false)` result is treated as a failure and reverts the whole operation (including the prior internal-state mutation), instead of being silently accepted as success.

### Proof of Concept
Given a substitute/compromised `sbtc-token` contract whose `transfer` is defined as:
```clarity
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (ok false)) ;; never actually moves any balance, but doesn't error
```
1. A staker calls `unstake-sbtc` for `amount-to-withdrawal-sats`.
2. pox-5 decrements `total-sbtc-staked` and the per-bond staked total by `amount-to-withdrawal-sats` [8](#0-7) .
3. pox-5 calls `(try! (contract-call? ... transfer amount-to-withdrawal-sats tx-sender staker none))`, which returns `(ok false)`; `try!` unwraps this to `false` and does not error [1](#0-0) .
4. The function returns `(ok result)` reporting success, even though the staker's sBTC balance never changed — the sBTC is now permanently stuck in the contract, unaccounted for by `total-sbtc-staked`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1309-1329)
```text
        (map-set protocol-bond-memberships staker
            (merge membership { amount-sats: new-amount-sats })
        )
        (map-set protocol-bonds-total-staked bond-index
            (- (get-total-sbtc-staked-for-bond bond-index)
                amount-to-withdrawal-sats
            ))

        ;; Mutate the total sBTC staked
        (var-set total-sbtc-staked
            (- current-total-sbtc-staked amount-to-withdrawal-sats)
        )

        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount-to-withdrawal-sats
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount-to-withdrawal-sats tx-sender staker none
            ))
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1943-1979)
```text
(define-private (roll-sbtc
        (staker principal)
        (old-sbtc uint)
        (new-sbtc uint)
    )
    (begin
        (if (> new-sbtc old-sbtc)
            (let ((delta (- new-sbtc old-sbtc)))
                (try! (contract-call?
                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    transfer delta tx-sender current-contract none
                ))
                (var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))
            )
            (if (< new-sbtc old-sbtc)
                (let ((delta (- old-sbtc new-sbtc)))
                    (try! (as-contract?
                        ((with-ft
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            "sbtc-token" delta
                        ))
                        (try! (contract-call?
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            transfer delta tx-sender staker none
                        ))
                    ))
                    (var-set total-sbtc-staked
                        (- (var-get total-sbtc-staked) delta)
                    )
                )
                ;; new-sbtc == old-sbtc, no transfer needed
                true
            )
        )
        (ok true)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2696-2713)
```text
(define-private (transfer-from-reserve
        (amount uint)
        (recipient principal)
    )
    (let ((cur-reserve (var-get reserve-balance)))
        (asserts! (>= cur-reserve amount) ERR_INSUFFICIENT_RESERVE_BALANCE)
        (var-set reserve-balance (- cur-reserve amount))
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount current-contract recipient none
            ))
        ))
        (ok true)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2724-2737)
```text
(define-private (transfer-stranded-rewards
        (amount uint)
        (recipient principal)
    )
    (begin
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount current-contract recipient none
            ))
        ))
        (ok true)
```
