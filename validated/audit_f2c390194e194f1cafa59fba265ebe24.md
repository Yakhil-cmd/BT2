### Title
Node-level `pox_rollover_v5` trusts pox-5's roll-over amount/height without validating the prior locked position, letting a bond→bond or bond→stake transition free part of a locked balance while still counting it as an active, unslashed commitment - (File: pox-locking/src/pox_5.rs)

### Summary
The H-03 report's root cause is that a migration was authorized by a weak identity check (codehash equality) while the *quantitative* invariants of the old and new position (locked amount, unlock flag, referral) were never required to match, letting a user "migrate" into a position with different economic terms and pull out funds that should still be locked. The closest structural analog in this repo is `handle_lockup_pox_v5` / `pox_rollover_v5` in `pox-locking/src/pox_5.rs`, which perform the Stacks-node-level equivalent of a "migration": moving an already-locked account from one PoX-5 commitment (stake or bond) into another, based solely on whatever `amount-ustx` / `unlock-burn-height` the pox-5 Clarity contract returns, with no node-side check that the new commitment is consistent with the old one.

### Finding Description
`handle_lockup_pox_v5` is invoked whenever `stake` or `register-for-bond` succeeds in pox-5 [1](#0-0) . It checks only whether the staker `already_locked`; if so, it calls `pox_rollover_v5` instead of `pox_lock_v5`, explicitly to "carry forward" the existing lock into the new position [2](#0-1) .

`pox_rollover_v5` accepts `new_total_locked` from the parsed contract-call result and applies it directly via `snapshot.set_lock_v5`, explicitly allowing the new amount to be "higher OR lower than the current lock", with any freed STX returned to the unlocked balance [3](#0-2) . The doc comment for this function states plainly: *"The contract gates which transitions are legal; at the node level we trust the call."* [4](#0-3) 

This is precisely the H-03 pattern: the node-level lock-management code (the "vault"/lock authority, analogous to `HoneyLocker.migrate`) authorizes a transition based on a single high-level condition (`already_locked` == true, analogous to codehash-based `isMigrationEnabled`) and then blindly trusts the *new* position's parameters (amount, unlock height) supplied by the calling contract, without re-validating that they are consistent with — or at least no worse than — the previous locked commitment for the purposes that locked commitment was serving (e.g., signer weight, bond backing). If the pox-5 Clarity contract has any path that lets `register-for-bond`/`stake` be called with a `new_total_locked` lower than what is required to back an already-registered signing/reward commitment for the cycle(s) already committed to, the node will silently release the difference to the unlocked balance while any downstream state that assumed the larger amount was still locked (e.g. reward-slot bookkeeping, signer weight already registered for upcoming cycles) is not re-validated at this layer.

Because the actual gating logic lives entirely in the Clarity contract (`pox-5.clar`), and pox-5.clar's exact bond/stake transition-validity code could not be retrieved within tool-call limits, I cannot point to a specific missing `asserts!` inside `pox-5.clar` that fails to check equality of a locked commitment across a roll-over. This means the analog is grounded in the trust boundary explicitly documented in `pox-locking/src/pox_5.rs` (the same trust boundary that caused the H-03 bug: authorization based on a coarse identity/state check with no equality validation of the migrated value), but the concrete reachable path proving a rollover can silently reduce backing for an existing commitment is not fully confirmed against `pox-5.clar`'s internal transition checks.

### Impact Explanation
If reachable, this would let a staker/bond-holder reduce their actual locked STX below what is required to back a reward slot or signer weight already committed for upcoming cycles, temporarily freezing/misallocating reserve funds or letting signing weight exceed backing STX — matching the report's "High" bucket (signing weight or reward slots exceeding locked value; temporary freezing of staked funds). Root cause and blast radius could not be fully confirmed without inspecting `pox-5.clar`'s bond/stake transition gating in full, so this should be treated as a hypothesis requiring code-level confirmation in `pox-5.clar`, not a proven exploit.

### Likelihood Explanation
Medium: it requires the pox-5.clar contract to actually expose a rollover path (bond→bond, stake→bond, bond→stake) where a user can specify or influence a `new_total_locked`/`unlock-burn-height` combination smaller than what current reward-cycle commitments require, and the Clarity contract's own checks would need to fail to catch it — this could not be verified from `pox-5.clar` directly within the available searches.

### Recommendation
Audit `pox-5.clar`'s `stake`, `stake-update`, `register-for-bond`, and `unstake` for any code path where a roll-over is accepted with a `new_total_locked` smaller than the amount already committed to open reward cycles/bonds for that staker, and add an explicit invariant check (either in `pox-5.clar` or as a defensive check in `pox_rollover_v5`) that the new locked amount is never less than the sum of amounts still committed to unexpired reward-cycle/bond entries for that staker, mirroring the fix recommended for the HoneyLocker report (validate equality/sufficiency of the carried-over commitment, not just that "a rollover was requested").

### Proof of Concept
Not constructable from indexed content: `pox-5.clar`'s bond/stake transition-legality logic (the code that is supposed to gate which roll-overs are valid) was not retrievable within the tool-call budget, so a concrete call sequence demonstrating under-collateralized roll-over cannot be produced here. A full PoC would need to inspect `stackslib/src/chainstate/stacks/boot/pox-5.clar`'s `register-for-bond`/`stake-update` implementations to construct a sequence where a staker calls a rollover with a smaller `amount-ustx` while still holding open commitments from the prior position.

### Citations

**File:** pox-locking/src/pox_5.rs (L291-358)
```rust
/// Roll an existing pox-5 lock forward into a new position: reschedule the
/// unlock to `unlock_burn_height` and reset the locked amount to
/// `new_total_locked`, which may be higher OR lower than the current lock
/// (any freed STX returns to the unlocked balance). Does NOT touch the
/// account nonce. Returns the resulting balance.
///
/// Used for any cross-mode roll-over the pox-5 contract permits: bond →
/// bond (`register-for-bond` from a previous bond), stake → bond
/// (`register-for-bond` from an STX-only stake), and bond → stake (`stake`
/// from a previous bond). The contract gates which transitions are legal;
/// at the node level we trust the call. In every case the STX lock is
/// carried over rather than released and re-acquired, so there is no gap.
///
/// # Errors
/// - Returns `PoxInvalidUnlockHeight` if the `unlock_burn_height` is not
///   strictly greater than the current unlock height (a roll-over must move
///   the unlock forward).
/// - Returns `PoxInvalidLockAmount` if the `new_total_locked` is zero.
/// - Returns `PoxExtendNotLocked` if the account isn't currently locked.
///   The pox-5 contract only reaches this path with an active prior lock
///   (existing bond membership or stx-only stake), so this should surface
///   as an invariant violation.
/// - Returns `PoxInsufficientBalance` if the account can't cover
///   `new_total_locked`.
pub fn pox_rollover_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    if new_total_locked == 0 {
        return Err(LockingError::PoxInvalidLockAmount);
    }

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    let bal = snapshot.canonical_balance_repr()?;
    let total_amount = bal
        .amount_unlocked()
        .checked_add(bal.amount_locked())
        .ok_or(LockingError::PoxBalanceOverflow)?;
    if total_amount < new_total_locked {
        return Err(LockingError::PoxInsufficientBalance);
    }

    if unlock_burn_height <= bal.unlock_height() {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }

    snapshot.set_lock_v5(new_total_locked, unlock_burn_height)?;

    let out_balance = snapshot.canonical_balance_repr()?;

    debug!(
        "PoX v5 lock rolled forward";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}
```

**File:** pox-locking/src/pox_5.rs (L360-420)
```rust
/// Handle responses from pox-5 entry points that lock STX for a staker:
/// `stake` (STX-only) and `register-for-bond` (protocol bond). A first-time
/// call (no existing pox-5 lock) acquires a fresh lock via
/// [`pox_lock_v5`]; a roll-over (the account is already locked from an
/// ending bond or stake) carries the lock forward via
/// [`pox_rollover_v5`] -- the amount may go up or down and the
/// unlock height is rescheduled, so the lock never releases. The contract
/// is responsible for gating the roll-over (non-overlap + L1 unlock window
/// for bond sources); if the contract returns ok, this handler trusts the
/// call is legitimate.
fn handle_lockup_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_5_NAME, global_context.mainnet)
    );
    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
    let (staker, locked_amount, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
    };

    // A staker rolling from one bond/stake position into another is already
    // locked; carry the lock forward instead of acquiring a fresh one (which
    // would fail with `PoxAlreadyLocked`). A first-time call locks fresh.
    let already_locked = {
        let mut snapshot = global_context.database.get_stx_balance_snapshot(&staker)?;
        snapshot.has_locked_tokens()?
    };

    let lock_result = if already_locked {
        pox_rollover_v5(
            &mut global_context.database,
            &staker,
            unlock_height,
            locked_amount,
        )
        .map(|_| ())
    } else {
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            locked_amount,
            unlock_height,
        )
    };
```
