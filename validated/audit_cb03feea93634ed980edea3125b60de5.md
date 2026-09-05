[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pox-locking/src/pox_5.rs (L53-119)
```rust
fn parse_pox_stake_result(result: &Value) -> Result<ParsedStakeResult, LockingError> {
    let response = result
        .clone()
        .expect_result()
        .map_err(|e| LockingError::PoxMalformedResponse(format!("not a response: {e:?}")))?;
    match response {
        Ok(res) => {
            let tuple_data = res.expect_tuple().map_err(|e| {
                LockingError::PoxMalformedResponse(format!("ok payload not a tuple: {e:?}"))
            })?;
            let staker = tuple_data
                .get("staker")
                .map_err(|_| LockingError::PoxMalformedResponse("missing 'staker'".into()))?
                .to_owned()
                .expect_principal()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'staker' is not a principal: {e:?}"
                    ))
                })?;

            let amount_ustx = tuple_data
                .get("amount-ustx")
                .map_err(|_| LockingError::PoxMalformedResponse("missing 'amount-ustx'".into()))?
                .to_owned()
                .expect_u128()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'amount-ustx' is not a uint: {e:?}"
                    ))
                })?;

            let unlock_burn_height_u128 = tuple_data
                .get("unlock-burn-height")
                .map_err(|_| {
                    LockingError::PoxMalformedResponse("missing 'unlock-burn-height'".into())
                })?
                .to_owned()
                .expect_u128()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'unlock-burn-height' is not a uint: {e:?}"
                    ))
                })?;
            let unlock_burn_height: u64 = unlock_burn_height_u128.try_into().map_err(|_| {
                LockingError::PoxMalformedResponse(format!(
                    "'unlock-burn-height' overflows u64: {unlock_burn_height_u128}"
                ))
            })?;

            Ok(ParsedStakeResult::Ok {
                staker,
                amount_ustx,
                unlock_burn_height,
            })
        }
        Err(e) => {
            // Validate the err payload shape — pox-5 is typed
            // `(response ... uint)`, so a non-uint here means the response
            // is malformed and should surface as such.
            e.expect_u128().map_err(|err| {
                LockingError::PoxMalformedResponse(format!("err payload not a uint: {err:?}"))
            })?;
            Ok(ParsedStakeResult::ContractErr)
        }
    }
}
```

**File:** pox-locking/src/pox_5.rs (L241-288)
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
```

**File:** pox-locking/src/pox_5.rs (L445-499)
```rust
fn handle_stake_lockup_update_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_5_NAME, global_context.mainnet),
    );

    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
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
        }
        Err(e) => Err(locking_error_to_vm_error(
            e,
            &format!(
                "pox-5 {function_name}: failed to extend lock from {staker} until {unlock_height}"
            ),
        )),
    }
}
```
