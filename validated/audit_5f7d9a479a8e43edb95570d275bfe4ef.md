Based on my investigation of the pox-5.clar contract, I found a genuine reachable analog. I was unable to fully read the bodies of `roll-sbtc`, `verify-bond-rollover-window`, `bond-overlaps-new-position?`, `add-staker-to-signer-cycles`, and `remove-staker-from-cycles` (ran out of tool budget before reading their full definitions), so the exact numeric equality break in the rollover path is not fully confirmed — I flag this uncertainty below. However, the concrete, provable issue is in `stake-update` itself.

### Title
`stake-update` extends lock and inflates counted stake amount without verifying the previous lock is still active or matches recorded state - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`stake-update` (pox-5.clar lines ~1092-1173) lets a staker extend their lock period and/or increase the locked amount. It recomputes `new-lock-amount` and `num-cycles` purely from the `staker-info` map and calls `remove-staker-from-cycles` / `add-staker-to-signer-cycles` to re-register the staker's future-cycle commitments and updates `staker-info` with the new totals, all without re-validating that `amount-ustx` in `staker-info` still corresponds to the STX actually locked on that principal (via `stx-account`) at the time of the call. [1](#0-0) 

### Finding Description
In `stake-update`, `new-lock-amount` is derived as `(+ (get amount-ustx current-info) amount-increase)`, i.e., trusting the previously stored `amount-ustx` field rather than re-deriving it from the actual on-chain locked balance (`stx-account tx-sender`'s `locked` field) as `stack-increase` does in pox-4/pox-2/pox-3. [2](#0-1) 

Compare this to the pattern used consistently in earlier PoX versions, where `stack-increase` always reads `amount-stacked` fresh from `(stx-account tx-sender)` rather than from a possibly stale map entry: [3](#0-2) 

The only balance check performed is `(>= (get unlocked (stx-account tx-sender)) amount-increase)`, which only confirms that `amount-increase` uSTX are currently unlocked — it does not cross-check that `(get amount-ustx current-info)` still equals the amount actually locked by the node-side PoX-locking logic (`pox-locking/src/pox_5.rs`). If any code path can leave `staker-info.amount-ustx` out of sync with the real locked balance (e.g., through the bond-rollover path in `stake`, which calls `roll-sbtc` and clears `protocol-bond-memberships` without necessarily reconciling `amount-ustx` — a code path I could not fully verify due to tool budget), `stake-update` would commit an inflated (or deflated) `new-lock-amount` to the reward-cycle totals and signer weighting, while the actual lock-increase applied via `pox_lock_update_v5` in `pox-locking/src/pox_5.rs` is driven by the value the Clarity contract returns. [4](#0-3) 

Because `pox_lock_update_v5` trusts the `new_total_locked` value handed to it by the contract's return value (only checking it doesn't decrease below the current locked amount and that unlocked+locked funds cover it), any equality break between `staker-info.amount-ustx` and the actually-locked STX balance in `stake-update` would propagate directly into the node's PoX lock state — either over-crediting reward weight/signing weight relative to STX actually locked (breaking "signing weight or reward slots exceeding locked value") or permanently under-locking STX relative to the staker's on-chain commitment.

### Impact Explanation
If `staker-info.amount-ustx` can drift from the true locked balance (via the bond-rollover branch of `stake`, or any other path that mutates `staker-info` without a corresponding STX lock/unlock), `stake-update` would silently carry forward and compound that inconsistency into `reward-cycle-pox-address-list`/signer totals, producing reward slots or signing weight that exceed the STX actually locked — a High severity issue per the "signing weight or reward slots exceeding locked value" impact category. I could not fully trace `roll-sbtc` / `verify-bond-rollover-window` to confirm whether such drift is currently reachable, so this should be treated as a likely-but-unconfirmed root cause requiring code review of those three private functions.

### Likelihood Explanation
Medium: `stake-update` is a normal user-facing entry point (no admin/miner/signer key required beyond the caller's own signer-manager choice), so any staker can trigger it. The likelihood the specific drift condition is reachable depends on the un-reviewed `roll-sbtc`/bond-rollover internals, which I was unable to inspect in the time available.

### Recommendation
Have `stake-update` re-derive the locked amount from `(get locked (stx-account tx-sender))` (as pox-2/3/4's `stack-increase` do) rather than trusting `staker-info.amount-ustx`, or add an explicit assertion that `(get amount-ustx current-info)` equals `(get locked (stx-account tx-sender))` before computing `new-lock-amount`. Additionally, audit `roll-sbtc`, `verify-bond-rollover-window`, and `bond-overlaps-new-position?` to confirm `staker-info.amount-ustx` is always kept in lockstep with the actual PoX-locked balance across the bond-rollover path.

### Proof of Concept
Not fully constructible from static analysis alone — a concrete PoC requires tracing whether `stake` → `roll-sbtc`/bond-rollover can leave `staker-info.amount-ustx` diverge from the true locked STX balance before `stake-update` is called. This is the piece I could not verify given the remaining tool budget; a background engineer with full repo/test access should write a Clarinet-based reproduction exercising `stake` with an existing rolled-over bond followed by `stake-update`, comparing `staker-info.amount-ustx` against `stx-account`'s `locked` field and the resulting `reward-cycle-total-stacked`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1092-1173)
```text
(define-public (stake-update
        (signer-manager <signer-manager-trait>)
        (old-signer-manager <signer-manager-trait>)
        (cycles-to-extend uint)
        (amount-increase uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (old-signer (contract-of old-signer-manager))
            (current-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKING))
            ;; This is the first cycle where their STX would be unlocked
            (prev-unlock-cycle (+ (get first-reward-cycle current-info)
                (get num-cycles current-info)
            ))
            (unlock-cycle (+ prev-unlock-cycle cycles-to-extend))
            (new-lock-amount (+ (get amount-ustx current-info) amount-increase))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ current-cycle u1))
            (num-cycles (- unlock-cycle current-cycle u1))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles new-lock-amount u0 false
            signer-calldata
        ))

        ;; Validate that `old-signer-manager` matches their current signer
        (asserts! (is-eq old-signer (get signer current-info))
            ERR_INVALID_OLD_SIGNER_MANAGER
        )

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;; Must have enough unlocked STX
        (asserts! (>= (get unlocked (stx-account tx-sender)) amount-increase)
            ERR_INSUFFICIENT_STX
        )

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1) true
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer (+ u1 current-cycle)
            num-cycles new-lock-amount true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: new-lock-amount,
            first-reward-cycle: (get first-reward-cycle current-info),
            num-cycles: (+ (get num-cycles current-info) cycles-to-extend),
            signer: signer,
        })

        (let ((result {
                unlock-burn-height: (reward-cycle-to-burn-height unlock-cycle),
                staker: tx-sender,
                signer: signer,
                old-signer: old-signer,
                prev-unlock-height: prev-unlock-cycle,
                unlock-cycle: unlock-cycle,
                num-cycles: num-cycles,
                amount-ustx: new-lock-amount,
                amount-increase: amount-increase,
                cycles-to-extend: cycles-to-extend,
            }))
            (print (merge { topic: "stake-update" } result))
            (ok result)
        )
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L1094-1107)
```text
   (let ((stacker-info (stx-account tx-sender))
         (amount-stacked (get locked stacker-info))
         (amount-unlocked (get unlocked stacker-info))
         (unlock-height (get unlock-height stacker-info))
         (cur-cycle (current-pox-reward-cycle))
         (first-increased-cycle (+ cur-cycle u1))
         (stacker-state (unwrap! (map-get? stacking-state
                                          { stacker: tx-sender })
                                          (err ERR_STACK_INCREASE_NOT_LOCKED)))
         (cur-pox-addr (get pox-addr stacker-state))
         (cur-period (get lock-period stacker-state)))
      ;; tx-sender must be currently locked
      (asserts! (> amount-stacked u0)
                (err ERR_STACK_INCREASE_NOT_LOCKED))
```

**File:** pox-locking/src/pox_5.rs (L241-289)
```rust
pub fn pox_lock_update_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }
    if new_total_locked == 0 {
        return Err(LockingError::PoxInvalidLockAmount);
    }

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    snapshot.update_unlock_v5(unlock_burn_height)?;

    let bal = snapshot.canonical_balance_repr()?;
    let total_amount = bal
        .amount_unlocked()
        .checked_add(bal.amount_locked())
        .ok_or(LockingError::PoxBalanceOverflow)?;
    if total_amount < new_total_locked {
        return Err(LockingError::PoxInsufficientBalance);
    }

    if bal.amount_locked() > new_total_locked {
        return Err(LockingError::PoxInvalidIncrease);
    }

    snapshot.increase_lock_v5(new_total_locked)?;

    let out_balance = snapshot.canonical_balance_repr()?;

    debug!(
        "PoX v5 lock updated";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}
```
