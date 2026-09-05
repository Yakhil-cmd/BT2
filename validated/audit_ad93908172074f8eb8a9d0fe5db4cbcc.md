## Finding [1](#0-0) 

### Title
`roll-sbtc` credits `total-sbtc-staked` with the *requested* sBTC amount instead of the amount actually received from `sbtc-token`, breaking the balance ⇄ accounting equality — (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
In `register-for-bond`'s sBTC-deposit path (`btc-lockup` supplied as `(err sbtc-amount)`), the private function `roll-sbtc` moves a staker's custodied sBTC by calling `sbtc-token transfer` for the computed `delta`, and then unconditionally increments the `total-sbtc-staked` data-var by that same requested `delta`, without ever re-checking the contract's actual sBTC balance delta: [2](#0-1) 

This is structurally identical to the reported bug class: the protocol trusts the transferred amount `amount` rather than verifying `amount actually received`, and then uses that unverified figure to update solvency-critical accounting (`get-rewards`, `get-new-rewards`, `calculate-rewards`) — [3](#0-2) .

### Finding Description
`get-rewards` derives the distributable reward pool as `current-balance - total-staked-sbtc - cur-reserve`, where `current-balance` is the *live* sBTC balance of the contract and `total-staked-sbtc` is the var `total-sbtc-staked` maintained solely through `roll-sbtc`'s bookkeeping [4](#0-3) . The invariant the protocol needs is:

`contract's actual sBTC balance == total-sbtc-staked + reserve-balance + distributable-rewards`

`roll-sbtc`'s increase branch does `(try! (contract-call? ... transfer delta tx-sender current-contract none))` and then does `(var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))` — crediting the full nominal `delta` regardless of what the contract's balance actually increased by [5](#0-4) . If the invoked `sbtc-token transfer` ever delivers less than `delta` to the contract (e.g. a future fee-on-transfer semantics change, a wrapper/pausable upgrade of that token, or any other deviation from strict 1:1 transfer), `total-sbtc-staked` becomes permanently inflated relative to the contract's real sBTC holdings. That inflation directly shrinks (or, once it exceeds `current-balance - cur-reserve`, causes an unsigned-subtraction runtime abort in) `get-rewards`/`get-new-rewards`, which are load-bearing for `calculate-rewards` [6](#0-5) .

The decrease branch of `roll-sbtc` has the same asymmetric trust: it also derives the payout `delta` purely from `old-sbtc - new-sbtc` bookkeeping rather than any balance check, and reduces `total-sbtc-staked` by that same nominal `delta` [7](#0-6) .

### Impact Explanation
Because `total-sbtc-staked` is not reconciled against the contract's actual sBTC balance at deposit time, any gap between "amount requested to transfer" and "amount actually received" — the exact scenario the external report describes for fee-on-transfer collateral — permanently corrupts the accounting equality between the contract's real sBTC holdings and the sum of staked + reserved + reward-pool sBTC. This can (a) permanently reduce/zero-out the reward pool that legitimate stakers should receive (silently freezing rewards), or (b) cause the unsigned subtraction in `get-rewards` to underflow and abort, which would break `calculate-rewards` for every bond going forward, effectively freezing reward distribution for all stakers.

### Likelihood Explanation
Under sBTC's current standard SIP-010 semantics (no transfer fee), the mismatch cannot occur today; it requires the canonical `sbtc-token` contract's transfer behavior to deviate from strict 1:1, which is outside pox-5's control. The root cause identified — pox-5 crediting the requested amount instead of verifying the received balance delta — is nonetheless pox-5's own accounting design flaw, matching the report's guidance that this class of finding is valid when the deposit logic itself never verifies actual amount received.

### Recommendation
In `roll-sbtc`, snapshot the contract's own `sbtc-token` balance immediately before and after the `transfer` call and credit/debit `total-sbtc-staked` by the observed balance delta rather than the nominal `delta` computed from `old-sbtc`/`new-sbtc`. This makes `total-sbtc-staked` self-correcting against whatever the token contract actually delivers, preserving the balance ⇄ accounting invariant `get-rewards` depends on.

### Proof of Concept
1. A staker calls `register-for-bond` with `btc-lockup` as `(err sbtc-amount)` for `sbtc-amount = N` sats, causing `roll-sbtc` to request a transfer of `delta = N` sats from the staker to the contract [8](#0-7) .
2. Suppose the `sbtc-token` transfer implementation (now or after any future change) delivers only `N - f` sats to the contract instead of `N` (fee-on-transfer style loss).
3. `roll-sbtc` still executes `(var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))` with the full `N`, so `total-sbtc-staked` is now `f` sats higher than the sBTC the contract actually custodies [5](#0-4) .
4. On the next `calculate-rewards` call, `get-rewards` computes `current-balance - total-staked-sbtc - cur-reserve`, which is now `f` sats short of the real reward pool available (or, if `f` accumulates enough, an unsigned-subtraction abort), corrupting reward accounting for all stakers going forward [9](#0-8) .

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L682-687)
```text
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1938-1956)
```text
;; Move a staker's custodied sBTC from `old-sbtc` to `new-sbtc`, transferring
;; only the net difference: pull the increase from the staker, or refund the
;; decrease. `total-sbtc-staked` is updated by the net change. A registration
;; with no rollover passes `old-sbtc` of `u0`, which transfers the full amount.
;; A no-op when the two are equal.
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1957-1972)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2134-2156)
```text
;; Returns the total balance of rewards received by the contract
(define-read-only (get-rewards)
    (let (
            (cur-reserve (var-get reserve-balance))
            (total-staked-sbtc (get-total-sbtc-staked))
            (current-balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
        )
        (- current-balance total-staked-sbtc cur-reserve)
    )
)

;; Returns the total amount of newly received sBTC rewards
;; since the last rewards computation
(define-read-only (get-new-rewards)
    (let (
            (last-accounted-rewards (var-get last-accounted-rewards-only))
            (rewards-balance (get-rewards))
        )
        (- rewards-balance last-accounted-rewards)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2168)
```text
(define-public (calculate-rewards (bond-periods (list 6 uint)))
    (let (
            (last-calc (var-get last-reward-compute-height))
            (calculation-height (- (distribution-cycle-to-burn-height (current-distribution-cycle))
                u1
            ))
            (cur-reserve (var-get reserve-balance))
            (gross-accrued-rewards (get-new-rewards))
            (stx-cycle (burn-height-to-reward-cycle calculation-height))
        )
        ;; ensure no reentrancy through signer-manager trait calls
```
