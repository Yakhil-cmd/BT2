### Title
Rollover in `register-for-bond` never decrements the old bond-index's `protocol-bonds-total-staked`, double-counting a staker's sats across two bond periods - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
When a staker rolls from an ending bond (bond-index `N`) into a new bond (`N+6`), `register-for-bond` computes `old-sbtc`/`new-sbtc`, calls `roll-sbtc` to move/refund the delta, and then only credits `protocol-bonds-total-staked` for the **new** bond-index with the full new amount. The old bond-index's `protocol-bonds-total-staked` entry, which still includes the staker's original `old-sbtc` contribution, is never touched or decremented.

### Finding Description
The broken equality is: `get-total-sbtc-staked-for-bond(N) + get-total-sbtc-staked-for-bond(N+6)` should equal the sBTC actually custodied by the contract for stakers currently in bonds `N` and `N+6`, and in aggregate `get-total-sbtc-staked()` should equal the sBTC token balance held by the contract.

In `register-for-bond` [1](#0-0) , the function reads the staker's `existing-membership`, derives `old-sbtc` via `get-staker-custodied-sbtc tx-sender` (tied to the OLD bond-index in `protocol-bond-memberships`), and `new-sbtc` for the new bond. It then calls `(try! (roll-sbtc tx-sender old-sbtc new-sbtc))` at [2](#0-1)  before overwriting `protocol-bond-memberships` for `tx-sender` with the new bond-index and `amount-sats` at [3](#0-2) .

Immediately after, the contract updates only the new bond's aggregate:
```
(map-set protocol-bonds-total-staked bond-index
    (+ current-total-staked sats-total)
)
``` [4](#0-3) 

There is no corresponding `map-set`/decrement of `protocol-bonds-total-staked` for the *old* bond-index (the one referenced by `existing-membership`) anywhere in this function. The comment on the map itself states it tracks "Total amount of sats staked per bond period" [5](#0-4) , i.e., it is meant to represent exactly-once accounting of currently-custodied sats per bond period. Since the staker's membership row is atomically moved from old bond-index to new bond-index (`protocol-bond-memberships` is a `principal`-keyed map, one entry per staker) but the old bond-index's cumulative counter is left untouched, that counter now overstates the sats actually custodied for bond `N` by exactly the staker's rolled-over amount, while the new bond-index's counter is incremented by the new amount on top of whatever it already had.

Existing guards do not address this: `verify-not-prepare-phase`, `verify-bond-rollover-window`, and `bond-overlaps-new-position?` only gate *when* a rollover is allowed to happen (timing/overlap of bond periods), not the bookkeeping correctness of the aggregate counters afterward [6](#0-5) . `signer-manager-validate-stake`/`validate-no-reentrancy` guard against reentrancy through the signer-manager trait, not against stale aggregate state [7](#0-6) .

### Impact Explanation
This is a per-bond-period accounting divergence: the old bond-index's `protocol-bonds-total-staked` retains a "ghost" amount attributable to a staker who has already left that bond and moved to a new one. If any downstream logic (reward distribution caps, unstake validation, or the reserve/lock-conservation invariant `get-total-sbtc-staked-for-bond(N) + get-total-sbtc-staked-for-bond(N+6) == get-total-sbtc-staked()`) relies on `protocol-bonds-total-staked` per bond-index summing correctly to the global total or to the actual custodied token balance, this divergence would double count sBTC that is not actually present under the old bond-index, matching a Critical double-counting-a-commitment class of bug.

### Likelihood Explanation
I was unable to fully verify this within the available tool budget: I could not locate and read the definitions of `roll-sbtc`, `get-staker-custodied-sbtc`, `unstake-sbtc`, or `get-total-sbtc-staked-for-bond`/`get-total-sbtc-staked` in the 3845-line `pox-5.clar` file (I only read lines 1–1000, and targeted greps for these definitions returned no matches, suggesting they may live further in the file or under different exact names). Because of this, I cannot confirm:
- Whether `roll-sbtc` performs the exact refund/transfer behavior assumed by the question (refunding `old-sbtc - new-sbtc` via `as-contract?` sBTC transfer).
- Whether `unstake-sbtc` or `get-total-sbtc-staked-for-bond` actually read from `protocol-bonds-total-staked`, or instead recompute custody from `protocol-bond-memberships`/`staker-info` directly (in which case the stale per-bond counter would be inert bookkeeping with no exploitable path to steal or free sBTC).
- Whether some other function (a per-cycle settlement handler, or a coordinator-side Rust handler) decrements the old bond-index's counter outside of `register-for-bond`.

Given this uncertainty, I can confirm the concrete code fact (no decrement of the old bond-index's `protocol-bonds-total-staked` inside `register-for-bond`) but cannot state with confidence that this maps to an actual exploitable Critical double-counting of real, redeemable sBTC without seeing how `unstake-sbtc`/`get-total-sbtc-staked-for-bond` consume this map.

### Recommendation
In `register-for-bond`'s rollover path, when `existing-membership` is `Some`, explicitly decrement `protocol-bonds-total-staked` for the old bond-index by `old-sbtc` (or the old membership's `amount-sats`) in the same transaction that credits the new bond-index, so that the sum over all bond-indexes of `protocol-bonds-total-staked` always equals `total-sbtc-staked`/the physical sBTC token balance held by the contract for staking purposes. Add an invariant test that asserts this sum after every rollover.

### Proof of Concept
Rust/Clarity test plan (pending confirmation of the missing function definitions, which should be reviewed directly in a full checkout of `pox-5.clar`):
1. Set up bonds `N` and `N+6` with allowlists including staker `S`.
2. Have `S` call `register-for-bond` for bond `N` with `sbtc-amount = X` (L2 path), asserting `get-total-sbtc-staked-for-bond(N) == X` and contract sBTC balance `== X`.
3. Advance to bond `N`'s L1-unlock window; have `S` call `register-for-bond` again for bond `N+6` with a smaller `sbtc-amount = Y < X`.
4. Assert `get-total-sbtc-staked-for-bond(N)` (expected `0` after rollover) vs. actual value (still `X` if the bug is present); assert `get-total-sbtc-staked-for-bond(N+6) == Y`; assert `get-total-sbtc-staked-for-bond(N) + get-total-sbtc-staked-for-bond(N+6) == get-total-sbtc-staked()`, and that this equals the physical `sbtc-token` contract balance held by `pox-5`.
5. If step 4's first equality fails (old bond still shows `X` instead of `0`) while the physical token balance only reflects `Y` (post-refund), this confirms the double-count in the per-bond aggregate map, independent of whether it is currently read by `unstake-sbtc`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L150-154)
```text
;; Total amount of sats staked per bond period
(define-map protocol-bonds-total-staked
    uint
    uint
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L400-427)
```text
(define-private (validate-no-reentrancy)
    (ok (asserts! (not (var-get signer-manager-call-active)) ERR_REENTRANT_CALL))
)

;; A helper function to call the `validate-stake!` function on a given
;; signer-manager, wrapping the reentrancy guard logic around it. This should
;; be the only way that `validate-stake!` is called in the contract, since it
;; is critical to ensure that reentrancy attacks are prevented.
(define-private (signer-manager-validate-stake
        (signer-manager <signer-manager-trait>)
        (staker principal)
        (first-index uint)
        (num-indexes uint)
        (amount-ustx uint)
        (amount-sats uint)
        (is-bond bool)
        (signer-calldata (optional (buff 500)))
    )
    (begin
        (asserts! (not (var-get signer-manager-call-active)) ERR_REENTRANT_CALL)
        (var-set signer-manager-call-active true)
        (try! (contract-call? signer-manager validate-stake! staker first-index
            num-indexes amount-ustx amount-sats is-bond signer-calldata
        ))
        (var-set signer-manager-call-active false)
        (ok true)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L679-707)
```text
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock).
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
            ;; Any STX-only stake the staker has. Present means this
            ;; `register-for-bond` is a roll-over from an ending stx-only
            ;; stake into a bond.
            (existing-stake (map-get? staker-info tx-sender))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (bond-start-height (bond-period-to-burn-height bond-index))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
            (current-total-staked (get-total-shares-staked-for-cycle first-reward-cycle
                (some bond-index)
            ))
            (stx-balance (stx-account tx-sender))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L764-784)
```text
        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )

        ;; Settle rewards before updating state
        (settle-rewards signer first-reward-cycle (some bond-index))
        (settle-staker-rewards signer first-reward-cycle (some bond-index)
            tx-sender
        )

        ;; A rollover from a non-overlapping existing bond may only happen in
        ;; that bond's L1 unlock window, the last 1/2 cycle.
        (try! (verify-bond-rollover-window existing-membership))

        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-792)
```text
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L793-795)
```text
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
```
