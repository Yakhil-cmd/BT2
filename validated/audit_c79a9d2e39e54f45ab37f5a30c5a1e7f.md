[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** pox-locking/src/pox_5.rs (L360-369)
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
```

**File:** pox-locking/src/pox_5.rs (L385-420)
```rust
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

**File:** pox-locking/src/pox_5.rs (L443-499)
```rust
/// Handle responses from `stake-update` in pox-5 -- the function that
/// *extends or increases already-locked* STX.
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

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L768-798)
```typescript
/**
 * `stake-update` checks only the *unlocked* balance against the requested
 * increase (distinct from `stake`'s total-balance rule), since the existing
 * stake is already locked.
 */
test('stake-update rejects an increase exceeding the unlocked balance', () => {
  const signer = testSigner.identifier;
  registerSigner();
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  expect(
    txErr(
      pox5.stakeUpdate({
        signerManager: signer,
        oldSignerManager: signer,
        cyclesToExtend: 1n,
        amountIncrease: stxToUStx(1_000_000_000_000_000),
        signerCalldata: null,
      }),
      alice,
    ).value,
  ).toBe(pox5Errors.ERR_INSUFFICIENT_STX);
```
