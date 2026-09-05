### Title
`unstake-sbtc` conflates sBTC bond-share accounting with a live sBTC-token transfer, freezing staked sBTC if the sBTC protocol reverts - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`unstake-sbtc` is the *only* unprivileged, on-chain path for a bond participant to recover custodied sBTC from pox-5. It first mutates all of the bond's internal accounting (per-cycle shares, `protocol-bonds-total-staked`, `total-sbtc-staked`, `protocol-bond-memberships`) and then, in the same atomic call, performs a mandatory `contract-call?` to the external `sbtc-token` contract to move the funds out. [1](#0-0) 

Because a Clarity transaction is all-or-nothing, if that external `transfer` call fails for any reason outside pox-5's control (the `sbtc-token`/`sbtc-registry` system pausing withdrawals, being upgraded, or being compromised), the entire `unstake-sbtc` call — including the accounting cleanup — reverts. There is no separate "record the exit intent" step and no fallback withdrawal path, unlike the reserve/rewards-pause escape hatches the contract does provide elsewhere (e.g. `transfer-from-reserve`, `transfer-stranded-rewards`, which are consensus-only levers, not staker-callable). [2](#0-1) 

This mirrors the M-13 pattern in the referenced report: an emergency/exit action is entangled with a mandatory external fund movement, so if the external call reverts, the exit itself becomes impossible, not just the fund transfer.

### Finding Description
`unstake-sbtc` is called directly by the staker (`tx-sender`), with no admin/pause-role requirement: [3](#0-2) 

It unconditionally chains the bond-cycle accounting update with the external transfer inside one `try!`-guarded sequence: [4](#0-3) 

`roll-sbtc` (used by `update-bond-registration`) exhibits the identical pattern when netting a decrease — it also requires a live `sbtc-token transfer` to succeed before the roll can complete: [5](#0-4) 

The `sbtc-token`/`sbtc-withdrawal`/`sbtc-registry` system is an independently upgradable external protocol (its interface is referenced by fixed principal, `SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4`), and pox-5's own `signer-manager.clar` reference implementation explicitly documents that this external system can be in unexpected states requiring bespoke recovery logic (`reclaim-failed-withdrawal`, `settle-accepted-withdrawal`, `sweep-fee-refunds`): [6](#0-5) 

Unlike that carefully-designed recovery flow for *rewards*, there is no equivalent recovery/decoupling mechanism for *principal* sBTC held via `unstake-sbtc`: the staker's only lever to reduce or exit their bond position requires the `sbtc-token transfer` to succeed in the same transaction.

### Impact Explanation
If the `sbtc-token` transfer reverts persistently (e.g., the external sBTC system pauses withdrawals, is paused in response to a hack, or is migrated/deprecated), every unprivileged staker's call to `unstake-sbtc` reverts along with the state cleanup it was trying to perform. The staker's custodied sBTC principal remains locked inside pox-5 with no alternative on-chain exit path, for as long as the external condition persists — a freezing of staked sBTC that the contract's own accounting says should be redeemable. This satisfies "temporary (or, if the external contract is permanently impaired, permanent) freezing of staked ... sBTC."

### Likelihood Explanation
The `sbtc-token` contract is external to pox-5 and can be upgraded or paused independently of pox-5 (pox-5 itself demonstrates awareness of such external-protocol failure modes with its `reclaim-failed-withdrawal`/`settle-accepted-withdrawal` machinery for rewards). No malicious pox-5 admin action, miner, or another user's key is required to trigger the freeze — only a state change in the external sBTC system, which is a realistic and previously-anticipated event (as evidenced by the reward-side recovery functions already present).

### Recommendation
Decouple the accounting mutation from the mandatory external transfer in `unstake-sbtc` (and `roll-sbtc`): first record the staker's withdrawal entitlement/liability (similar to `withdrawal-liability` used for L1 withdrawals), then allow the actual `sbtc-token transfer` to be retried permissionlessly in a separate call, so a temporarily-failing external transfer cannot block the staker's underlying exit accounting from being finalized.

### Proof of Concept
1. Alice registers for an sBTC bond and stakes sats via `register-for-bond`, becoming a `protocol-bond-memberships` entry.
2. The external `sbtc-token` contract's withdrawal/transfer path becomes unavailable (paused/upgraded/hacked) — outside pox-5's control.
3. Alice calls `unstake-sbtc` (`stackslib/src/chainstate/stacks/boot/pox-5.clar:1261-1342`). The accounting steps at lines 1299-1319 execute in-memory, but the mandatory `contract-call? ... sbtc-token transfer` at lines 1326-1328 fails.
4. Because Clarity transactions are atomic, the whole call — including the accounting updates that would have released Alice's position — reverts. Alice cannot unstake any amount of her sBTC through any other path until the external `sbtc-token` contract's transfer path is functional again.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1261-1330)
```text
(define-public (unstake-sbtc
        (signer-manager <signer-manager-trait>)
        (amount-to-withdrawal-sats uint)
    )
    (let (
            (staker tx-sender)
            (membership (unwrap! (map-get? protocol-bond-memberships staker)
                ERR_NOT_BOND_PARTICIPANT
            ))
            (bond-index (get bond-index membership))
            (signer (get signer membership))
            (current-cycle (current-pox-reward-cycle))
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (first-changed-reward-cycle (clamp current-cycle bond-start-cycle bond-end-cycle))
            (num-cycles (- bond-end-cycle first-changed-reward-cycle))
            (current-amount-sats (get amount-sats membership))
            (current-total-sbtc-staked (get-total-sbtc-staked))
            ;; Cannot withdrawal more than they've staked
            (new-amount-sats (try! (if (<= amount-to-withdrawal-sats current-amount-sats)
                (ok (- current-amount-sats amount-to-withdrawal-sats))
                ERR_INVALID_UNSTAKE_SBTC_AMOUNT
            )))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; `signer-manager` must match the current signer
        (asserts! (is-eq (contract-of signer-manager) signer)
            ERR_INVALID_OLD_SIGNER_MANAGER
        )

        ;; Must be an sBTC lock
        (asserts! (not (get is-l1-lock membership)) ERR_CANNOT_UNSTAKE_SBTC)

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Unstake this staker's sBTC from the current and future cycles.
        ;; N.B. Because the staker might use a different signer for the current
        ;; cycle vs future cycles (through `update-bond-registration`), we must
        ;; derive the signer from each cycle individually (instead of using
        ;; `remove-staker-from-bond-cycles`).
        (try! (unstake-sats-from-bond-cycles staker bond-index
            first-changed-reward-cycle num-cycles amount-to-withdrawal-sats
            new-amount-sats
        ))

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1956-1972)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2692-2739)
```text
;; Transfer funds from reserve. This is private and not called anywhere in the
;; contract, so it can only be called by the node as part of consensus (via the
;; SIP process).
;; #[allow(unused_private_fn)]
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

;; Transfer funds stranded by a rewards pause. This is private and not called
;; anywhere in the contract, so it can only be called by the node as part of
;; consensus (via the SIP process).
;;
;; Unlike `transfer-from-reserve`, which updates internal state and requires
;; that the amount is less than the reserve, this function
;; can act as a "catch-all" for transferring sBTC from this contract (via a
;; hard fork).
;; #[allow(unused_private_fn)]
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
    )
)
```

**File:** contrib/core-contract-tests/tests/pox-5/signer-manager-refunds.test.ts (L20-29)
```typescript
// Regression tests for POX5-M04: L1 withdrawal fee refunds were not returned to
// stakers. A staker's pox-5 balance is zeroed the moment `claim-staker-rewards`
// initiates the sBTC withdrawal, but because the signer-manager contract is the
// withdrawal's requester, any sBTC the sBTC protocol returns lands on the
// contract, not the staker. The fix adds:
//   * `reclaim-failed-withdrawal` (permissionless) -- pays a REJECTED
//     withdrawal's full `amount + max-fee` back to the mapped staker.
//   * `settle-accepted-withdrawal` (permissionless) -- retires an ACCEPTED
//     withdrawal's liability so its unused-fee dust becomes sweepable.
//   * `sweep-fee-refunds` (admin-gated) -- recovers the accept-case dust.
```
