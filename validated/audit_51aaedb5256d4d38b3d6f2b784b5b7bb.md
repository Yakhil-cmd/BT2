[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pox-locking/src/pox_5.rs (L130-156)
```rust
fn locking_error_to_vm_error(e: LockingError, ctx: &str) -> VmExecutionError {
    match e {
        LockingError::DefunctPoxContract => {
            VmExecutionError::Runtime(RuntimeError::DefunctPoxContract, None)
        }
        LockingError::PoxAlreadyLocked => {
            VmExecutionError::Runtime(RuntimeError::PoxAlreadyLocked, None)
        }
        LockingError::Clarity(err) => err,
        // Exhaustively match the remaining variants so adding a new one
        // forces a decision here instead of silently falling through to
        // `VmInternalError::Expect`. If a future variant is user-visible,
        // give it its own arm above; if it really is an invariant
        // violation, add it to this list.
        e @ (LockingError::PoxInsufficientBalance
        | LockingError::PoxExtendNotLocked
        | LockingError::PoxIncreaseOnV1
        | LockingError::PoxInvalidIncrease
        | LockingError::PoxUnstakeNotLocked
        | LockingError::PoxInvalidLockAmount
        | LockingError::PoxInvalidUnlockHeight
        | LockingError::PoxBalanceOverflow
        | LockingError::PoxMalformedResponse(_)) => VmExecutionError::Internal(
            VmInternalError::Expect(format!("{ctx}: pox-5 invariant violated: {e:?}")),
        ),
    }
}
```

**File:** pox-locking/src/pox_5.rs (L388-395)
```rust
    let (staker, locked_amount, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
    };
```

**File:** pox-locking/src/pox_5.rs (L422-440)
```rust
    match lock_result {
        Ok(()) => {
            // Log the staking in the asset map
            global_context.log_stacking(&staker, locked_amount)?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: staker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(e) => Err(locking_error_to_vm_error(
            e,
            &format!("pox-5 {function_name}: failed to lock {locked_amount} from {staker} until {unlock_height}"),
        )),
    }
```

**File:** pox-locking/src/pox_5.rs (L984-1000)
```rust
    #[test]
    fn handle_stake_lockup_insufficient_balance_returns_internal_error() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 100_000;
        let lock_amount = 500_000u128; // more than the account has

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        let response = make_stake_ok_response(&staker, lock_amount, 10_000);
        // The contract is supposed to prevent this; hitting this path used
        // to panic but now surfaces as a graceful Internal/Expect error.
        let err = handle_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect_err("expected an Internal error");
        match err {
            VmExecutionError::Internal(VmInternalError::Expect(_)) => {}
            other => panic!("expected Internal/Expect, got: {other:?}"),
```
