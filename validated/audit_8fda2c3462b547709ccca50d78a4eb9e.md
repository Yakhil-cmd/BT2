### Title
Bond stakers leaving/expiring never remove the signer from the signer-set linked list or decrement its delegated total, causing stale over-counted signer weight - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
The Prysm fix addresses an asymmetric cleanup bug: one code path (removing children of *empty* forkchoice nodes) maintained an invariant, while a parallel path (removing children of *full* nodes) did not, leaving stale tree state. `pox-5.clar` has the same asymmetry between its two staker-removal code paths that both mutate the shared `signer-set-ll-for-cycle` linked list and `signer-delegated-per-cycle` total: the STX-only unstake path enforces the "signer stays in the set only while delegated ≥ `SIGNER_SET_MIN_USTX`" invariant, but the protocol-bond exit path does not.

### Finding Description
`add-staker-to-signer-for-cycle` [1](#0-0)  explicitly treats "amount delegated to a signer" as the sum of protocol-bond and STX-only staking, and when that combined total crosses `SIGNER_SET_MIN_USTX` it calls `add-signer-to-set-for-cycle` to insert the signer into the per-cycle linked list [2](#0-1) , and it updates `signer-delegated-per-cycle` to the new combined total.

When an STX-only staker leaves, `remove-staker-from-signer-for-cycle` recomputes `new-delegated` and, if it has fallen below `SIGNER_SET_MIN_USTX`, calls `remove-staker-from-set-for-cycle` to unlink the signer from `signer-set-ll-for-cycle`/`signer-set-ll-first-for-cycle`/`signer-set-ll-last-for-cycle`, and also writes the decremented value to `signer-delegated-per-cycle` [3](#0-2) .

The parallel bond-exit path, `remove-staker-from-bond-for-cycle`/`remove-staker-from-bond-cycles`, only decrements `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and zeroes `staker-shares-staked-for-cycle` [4](#0-3) . It never re-reads or decrements `signer-delegated-per-cycle`, never re-checks `SIGNER_SET_MIN_USTX`, and never calls `remove-staker-from-set-for-cycle`. Consequently a signer whose entire eligibility came from bond delegation (or whose bond delegation was what pushed it over the threshold) stays in `signer-set-ll-for-cycle` forever, with `signer-delegated-per-cycle` permanently reporting an inflated (never-decremented) amount, even though the underlying bond stake that earned that membership has fully unwound.

This is structurally the same class of bug as the Prysm forkchoice fix: two code paths mutate a shared linked structure and its aggregate counters under a common invariant, but only one of the two removal paths performs the cleanup/invariant check, leaving the shared structure in a state inconsistent with the actual underlying committed value.

### Impact Explanation
The signer-set linked list and `signer-delegated-per-cycle`/`get-amount-delegated-for-signer` drive the pox-5 signer-set membership and weighting logic consumed by `pox_5_make_signer_set` in the Nakamoto signer-set construction [5](#0-4) . A signer permanently retained in the linked list with a stale/inflated delegated amount can continue to be counted for signing weight/reward-slot allocation that is no longer backed by any locked STX/sats, breaking the invariant that signer weight or reward-slot share must not exceed currently locked/delegated value. This matches the "High" impact category: signing weight or reward slots exceeding locked value.

### Likelihood Explanation
This is reachable through ordinary, unprivileged user action: any staker can register a protocol bond that pushes a signer over `SIGNER_SET_MIN_USTX`, and then let that bond's stacking period end/expire (or otherwise trigger the bond-removal path), which invokes `remove-staker-from-bond-cycles`/`remove-staker-from-bond-for-cycle`. No admin, miner, or privileged role is required — only ordinary bond stake/unstake lifecycle transitions already exposed by the contract.

### Recommendation
Make `remove-staker-from-bond-for-cycle` mirror `remove-staker-from-signer-for-cycle`: recompute `get-amount-delegated-for-signer`, decrement `signer-delegated-per-cycle` by the removed amount, and if the resulting total falls below `SIGNER_SET_MIN_USTX` while the signer is still linked (`get-signer-set-item-for-cycle`), call `remove-staker-from-set-for-cycle` to unlink it — exactly as done on the STX-only removal path.

### Proof of Concept
1. Signer S has no STX-only stakers; a staker registers a protocol bond delegating `amount ≥ SIGNER_SET_MIN_USTX` to S for cycle N via the path that calls `add-staker-to-signer-for-cycle`, which inserts S into `signer-set-ll-for-cycle` for cycle N and sets `signer-delegated-per-cycle = amount`.
2. The bond reaches its exit/expiry point and the removal path invokes `remove-staker-from-bond-cycles` → `remove-staker-from-bond-for-cycle` for cycle N.
3. Observe that `signer-delegated-per-cycle` for (S, N) is unchanged (still `amount`), and `get-signer-set-item-for-cycle(S, N)` still returns `Some` — S remains in the linked list and continues to be enumerated/weighted by `pox_5_make_signer_set`/`StakeEntryIteratorPox5`, despite having zero actual bond or STX-only stake backing it for cycle N.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1539-1616)
```text
            (new-delegated (- cur-delegated-for-signer amount))
            (is-in-signer-set (is-some (get-signer-set-item-for-cycle signer reward-cycle)))
        )
        ;; Settle STX-only rewards before mutating anything
        (settle-rewards signer reward-cycle none)
        (settle-staker-rewards signer reward-cycle none staker)

        (if is-in-signer-set
            (if (< new-delegated SIGNER_SET_MIN_USTX)
                ;; They've crossed back below the threshold - remove from the signer set
                ;; and remove from reward calculations.
                (begin
                    (try! (remove-staker-from-set-for-cycle signer reward-cycle))
                    (map-set signer-shares-staked-for-cycle {
                        reward-cycle: reward-cycle,
                        signer: signer,
                        bond-index: none,
                    }
                        u0
                    )
                    (map-set total-shares-staked-for-cycle {
                        reward-cycle: reward-cycle,
                        bond-index: none,
                    }
                        (- total-shares-staked cur-staked-for-signer)
                    )
                )
                ;; They are in the signer set - update reward calculations
                (begin
                    (map-set total-shares-staked-for-cycle {
                        reward-cycle: reward-cycle,
                        bond-index: none,
                    }
                        (- total-shares-staked stake-amount)
                    )
                    (map-set signer-shares-staked-for-cycle {
                        reward-cycle: reward-cycle,
                        bond-index: none,
                        signer: signer,
                    }
                        (- cur-staked-for-signer stake-amount)
                    )
                )
            )
            true
        )
        ;; Remove this staker from this signer
        (map-delete staker-signer-cycle-memberships {
            staker: staker,
            cycle: reward-cycle,
        })
        ;; Update amount delegated
        (map-set signer-delegated-per-cycle {
            cycle: reward-cycle,
            signer: signer,
        }
            new-delegated
        )
        ;; Remove amount for staker
        (map-delete staker-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: none,
            staker: staker,
            signer: signer,
        })
        ;; Update amount staked
        (map-set signer-pending-staked-ustx-per-cycle {
            signer: signer,
            cycle: reward-cycle,
        }
            (- (get-signer-pending-staked-ustx-per-cycle signer reward-cycle)
                stake-amount
            ))
        ;; Update total amount delegated this cycle
        (map-set ustx-delegated-per-cycle reward-cycle
            (- (get-ustx-delegated-for-cycle reward-cycle) amount)
        )
        (ok accumulator)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1652-1662)
```text
;; For a given (staker, signer, cycle), update signer state for that
;; cycle and lazily add the signer to the signer set if needed.
;;
;; We also update state for the total STX delegated to this signer,
;; along with the total of STX staked in STX-only staking for this signer.
;;
;; If the signer is above the minimum threshold, only then do we update
;; reward calculation state, so that signers below the _delegation_ threshold
;; don't receive rewards. This means it's possible for a signer to have
;; _more_ than the minimum delegated, but _less_ staked from STX-only stakers,
;; but they'll still receive rewards.
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1705-1717)
```text
        (if (>= new-delegated SIGNER_SET_MIN_USTX)
            (begin
                (map-set signer-shares-staked-for-cycle {
                    reward-cycle: cycle,
                    bond-index: none,
                    signer: signer,
                }
                    (+ prev-staked stake-amount)
                )
                (if (< cur-delegated-for-signer SIGNER_SET_MIN_USTX)
                    ;; They just crossed the threshold - add to signer set and add to reward calculations
                    (begin
                        (add-signer-to-set-for-cycle signer cycle)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1887-1936)
```text
(define-private (remove-staker-from-bond-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            signer: principal,
            staker: principal,
            bond-index: uint,
            amount-sats: uint,
            first-reward-cycle: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (reward-cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (signer (get signer accumulator))
            (bond-index (get bond-index accumulator))
            (amount-sats (get amount-sats accumulator))
            (current-total-staked (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (current-signer-staked (get-signer-shares-staked-for-cycle signer reward-cycle
                (some bond-index)
            ))
        )
        ;;  Update total shares staked for this cycle
        (map-set total-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
        }
            (- current-total-staked amount-sats)
        )
        ;;  Update total shares for this signer
        (map-set signer-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
        }
            (- current-signer-staked amount-sats)
        )
        ;;  Update staker's shares
        (map-set staker-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
            staker: (get staker accumulator),
        }
            u0
        )
        (ok accumulator)
    )
)
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L337-352)
```rust
/// as produced by walking pox-5's per-cycle signer-set linked list.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RawPox5Entry {
    pub(crate) amount_ustx: u128,
    pub(crate) signer_key: [u8; SIGNERS_PK_LEN],
}

/// Walks the pox-5 per-cycle signer-set linked list, yielding one
/// `RawPox5Entry` per registered signer for the cycle.
pub struct StakeEntryIteratorPox5<'a, 'b, 'c> {
    current_signer: Option<PrincipalData>,
    pox_contract: QualifiedContractIdentifier,
    clarity: &'a mut ClarityTransactionConnection<'b, 'c>,
    reward_cycle_clar: SymbolicExpression,
}

```
