[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** pox-locking/src/pox_5.rs (L360-403)
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
```

**File:** pox-locking/src/pox_5.rs (L571-583)
```rust

    // Record a position-altering PoX action for the affected staker (always
    // `tx-sender`, i.e. `sender_opt`), so that transaction-level `Pox`
    // post-conditions and `with-pox` allowances can constrain them. Recorded
    // whether or not the call succeeded, so an allowance can gate even a failed
    // attempt.
    if matches!(
        function_name,
        "unstake" | "unstake-sbtc" | "update-bond-registration" | "announce-l1-early-exit"
    ) {
        if let Some(staker) = sender_opt {
            global_context.log_pox_action(staker)?;
        }
```

**File:** pox-locking/src/pox_5.rs (L1333-1349)
```rust
    #[test]
    fn parse_pox_stake_result_ok_register_for_bond() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let response = make_register_for_bond_ok_response(&staker, 750_000, 12_000);
        match parse_pox_stake_result(&response).expect("parse should succeed") {
            ParsedStakeResult::Ok {
                staker: parsed_staker,
                amount_ustx,
                unlock_burn_height,
            } => {
                assert_eq!(parsed_staker, staker);
                assert_eq!(amount_ustx, 750_000);
                assert_eq!(unlock_burn_height, 12_000);
            }
            ParsedStakeResult::ContractErr => panic!("expected Ok, got ContractErr"),
        }
    }
```
