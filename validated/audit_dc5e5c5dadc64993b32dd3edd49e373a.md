### Title
Roll-over via `register-for-bond` double-counts departed staker's sBTC in `protocol-bonds-total-staked` for the ending bond - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
When a staker rolls from an ending bond A into a new bond B with `sats-total == old-sbtc`, `roll-sbtc` correctly performs no physical sBTC transfer, but `register-for-bond` only updates bond B's `protocol-bonds-total-staked` entry and never decrements bond A's. This leaves bond A's recorded total sBTC staked inflated by the departed staker's `S` sats even though the physical sBTC now backs bond B, and the contract's own comments confirm this is by design rather than an oversight elsewhere in the code.

### Finding Description
The invariant that should hold is: `sum(protocol-bonds-total-staked[A], protocol-bonds-total-staked[B])` should equal the actual physical sBTC custodied by pox-5 attributable to the rolling staker (`S`), not `2S`.

In `register-for-bond` [1](#0-0) , the roll-over path calls `roll-sbtc tx-sender old-sbtc new-sbtc` where `old-sbtc` is read from the ending bond A's membership `amount-sats` and `new-sbtc` is the caller-supplied `sats-total` for bond B. Inside `roll-sbtc` [2](#0-1) , when `new-sbtc == old-sbtc` no transfer occurs (documented explicitly as a no-op at line 1973).

Immediately after, `register-for-bond` overwrites the staker's `protocol-bond-memberships` row to point at bond B, and updates only bond B's `protocol-bonds-total-staked[bond-index]` by adding `sats-total` [3](#0-2) . Bond A's own `protocol-bonds-total-staked` entry (keyed by bond A's index) is never touched in this function. The code's own comment makes this explicit: "A roll-over from an ending bond ADDS the new bond's shares but does NOT tear down the old bond's per-cycle shares/delegation (unlike `update-bond-registration`, which removes then re-adds)" [4](#0-3) .

Because the roll-over is only permitted "in that bond's L1 unlock window, the last 1/2 cycle" (`verify-bond-rollover-window`) [5](#0-4) , bond A is still within its active reward-cycle window when the staker exits, meaning bond A's total-staked figure — used for `get-total-sbtc-staked-for-bond` and per-bond signer-weight computations for that overlapping cycle — still counts the departed staker's `S` sats as backing bond A, while bond B's total simultaneously counts the same physical `S` sats.

None of the existing guards (`verify-not-prepare-phase`, `verify-bond-rollover-window`, `check-pox-lock-period`, `verify-signer-key-grant`) address this because they gate *when* a rollover is allowed, not *what accounting entries* are updated as part of it. The only place that tears down a bond's per-cycle totals on exit is `update-bond-registration`'s remove/re-add path, which is explicitly bypassed for roll-overs by design per the comment.

### Impact Explanation
Bond A's per-bond `protocol-bonds-total-staked` (and therefore `get-total-sbtc-staked-for-bond(A)`) remains inflated by `S` sats that no longer physically back bond A for the remainder of the overlapping cycle, while bond B's corresponding total also counts the same `S` sats — a double count of a single physical sBTC commitment across two bond indices. This corrupts per-bond signer-weight/collateral accounting for the affected cycle. This matches the Critical category "double-counting a commitment" as defined by the audit rules. The condition is repeatable by any staker performing a same-amount roll-over during the unlock window of any bond, at no cost beyond ordinary transaction fees.

### Likelihood Explanation
Preconditions are attacker-controllable and require no privileged role: an existing staker in bond A near the end of its term, during the documented L1 unlock window, calling `register-for-bond` for bond B with `sats-total` set exactly equal to their existing `amount-sats` in bond A. This is a normal, expected roll-over flow (the contract explicitly supports and documents this rollover pattern), so likelihood of triggering the discrepancy is high and it is deterministic, not probabilistic.

### Recommendation
On roll-over from an existing, non-overlapping bond membership, decrement the old bond's `protocol-bonds-total-staked[old-bond-index]` by `old-sbtc` (mirroring the tear-down performed in `update-bond-registration`) before/while adding `sats-total` to the new bond's entry, so that the sum of both entries always reflects the singly-counted physical sBTC.

### Proof of Concept
Rust integration test outline (in `stacks-node/src/tests/pox_5_integrations.rs`, following existing `RegisterForBondRolloverFromStake`-style patterns):
1. Set up bond A and bond B contiguous bonds (B starts immediately after A's L1 unlock window opens).
2. Register staker for bond A with `amount-sats = S`, lock L1 sBTC of `S`.
3. Advance to bond A's L1 unlock window.
4. Call `register-for-bond` for bond B with `sats-total = S` (equal to bond A's `amount-sats`), triggering the `old-sbtc == new-sbtc` no-op path in `roll-sbtc`.
5. Read `get-total-sbtc-staked-for-bond(A)` and `get-total-sbtc-staked-for-bond(B)`.
6. Assert `get-total-sbtc-staked-for-bond(A) + get-total-sbtc-staked-for-bond(B) == S` (single physical custody) — this assertion fails, instead observing `2 * S`, confirming the double count.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L778-780)
```text
        ;; A rollover from a non-overlapping existing bond may only happen in
        ;; that bond's L1 unlock window, the last 1/2 cycle.
        (try! (verify-bond-rollover-window existing-membership))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L782-795)
```text
        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))

        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L796-801)
```text
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
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
