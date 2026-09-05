[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** pox-locking/src/pox_5.rs (L464-490)
```rust
    let (staker, amount_ustx, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
    };

    match pox_lock_update_v5(
        &mut global_context.database,
        &staker,
        unlock_height,
        amount_ustx,
    ) {
        Ok(_) => {
            // Log the extension in the asset map.
            global_context.log_stacking(&staker, amount_ustx)?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount: amount_ustx,
                    unlock_height,
                    locked_address: staker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
```
