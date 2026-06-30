### Title
Missing Pending-Deployment Flag in XCC Precompile Allows Repeated `STORAGE_AMOUNT` wNEAR Drain Before Callback Resolves - (File: `engine-precompiles/src/xcc.rs`)

---

### Summary

The `CrossContractCall` precompile charges a user `STORAGE_AMOUNT` (2 NEAR worth) of wNEAR when their router sub-account does not yet exist. The flag that marks the router as "deployed" (`get_code_version_of_address`) is only written asynchronously inside the `factory_update_address_version` callback. No synchronous "pending" flag is set at the moment the first XCC call is made. A user who submits two XCC transactions before that callback executes is charged `STORAGE_AMOUNT` twice; the second charge's wNEAR is permanently frozen in the engine's implicit EVM address because the downstream promise chain fails when the second `CreateAccount` batch is rejected by the NEAR runtime.

---

### Finding Description

**Root cause — synchronous read, asynchronous write, no pending guard.**

In `engine-precompiles/src/xcc.rs`, `run_with_handle` decides whether to charge `STORAGE_AMOUNT` by reading the on-chain version record:

```rust
let required_near =
    match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
        None => attached_near + state::STORAGE_AMOUNT,
        Some(_) => attached_near,
    };
``` [1](#0-0) 

When `required_near != ZERO_YOCTO`, the precompile immediately executes an EVM-level `transferFrom` that moves the user's wNEAR to the engine's implicit address: [2](#0-1) 

The version record is only written inside `factory_update_address_version`, which is an asynchronous NEAR callback attached to the deployment batch: [3](#0-2) 

The callback is scheduled in `handle_precompile_promise` only after the deployment batch succeeds: [4](#0-3) 

Between the moment the first XCC EVM transaction executes and the moment `factory_update_address_version` writes the version to storage (next NEAR block or later), `get_code_version_of_address` still returns `None` for the sender's address. Any second XCC EVM transaction submitted in the same window will therefore also enter the `create_needed = true` branch, charge the user another `STORAGE_AMOUNT` in wNEAR, and schedule a second `CreateAccount` batch.

**Why the second charge's wNEAR is permanently frozen.**

The second `CreateAccount` batch fails at the NEAR runtime level because the sub-account already exists. NEAR callbacks are always invoked regardless of prior promise success or failure. The downstream chain is:

```
batch(CreateAccount…) → factory_update_address_version → withdraw_wnear_to_router → send_refund → execute/schedule
```

`withdraw_wnear_to_router` explicitly aborts when its predecessor failed: [5](#0-4) 

Because `withdraw_wnear_to_router` never executes, the wNEAR that was already transferred to the engine's implicit EVM address in the second EVM transaction is never unwrapped and forwarded to the router. The engine's implicit address has no private key and no recovery path; the wNEAR is permanently frozen there.

---

### Impact Explanation

**Permanent freezing of user funds.** The user's wNEAR (equal to `STORAGE_AMOUNT` = 2 NEAR) is transferred to the engine's implicit EVM address during the second EVM transaction and cannot be recovered. The engine's implicit address (`near_account_to_evm_address(engine_account_id)`) is not controlled by any key; no EVM transaction can be signed from it to move the tokens out. [6](#0-5) 

---

### Likelihood Explanation

**Medium.** The window of vulnerability is one NEAR block (the gap between the first XCC EVM transaction and the `factory_update_address_version` callback). In Aurora, multiple EVM transactions are batched into a single NEAR block via the `submit` entrypoint. A user who submits two XCC calls in rapid succession — a common pattern when chaining operations — will naturally hit this window. No adversarial action is required; the user inflicts the loss on themselves through ordinary usage. A malicious relayer could also deliberately delay callback inclusion to widen the window.

---

### Recommendation

Set a synchronous "pending deployment" sentinel in storage at the moment the first XCC call is made (e.g., write a special `PENDING` version value for the address). `get_code_version_of_address` should treat `PENDING` as equivalent to `Some(_)` so that subsequent calls do not re-enter the `create_needed = true` branch. Clear the sentinel and write the real version in `factory_update_address_version`. Alternatively, treat any non-`None` storage entry (including a pending marker) as proof that deployment is already in flight and skip the `STORAGE_AMOUNT` charge. [1](#0-0) [7](#0-6) 

---

### Proof of Concept

1. User has no router sub-account (`get_code_version_of_address` returns `None`).
2. User submits **EVM tx 1** calling the XCC precompile. The precompile charges `STORAGE_AMOUNT` wNEAR via `transferFrom` (EVM-level, synchronous). A NEAR promise batch is scheduled: `CreateAccount + Transfer(STORAGE_AMOUNT) + DeployContract + initialize`, followed by `factory_update_address_version`.
3. Before `factory_update_address_version` executes (i.e., in the same NEAR block or the next one before the callback receipt is processed), user submits **EVM tx 2** calling the XCC precompile again. `get_code_version_of_address` still returns `None`. The precompile charges another `STORAGE_AMOUNT` wNEAR and schedules a second identical deployment batch.
4. First batch executes → router account created → `factory_update_address_version` writes the version.
5. Second batch executes → `CreateAccount` fails (account exists) → `factory_update_address_version` receives `Some(false)`, returns error → `withdraw_wnear_to_router` receives `Some(false)`, returns `ERR_CALLBACK_OF_FAILED_PROMISE` → `send_refund` panics on `require_no_failed_promises`.
6. The `STORAGE_AMOUNT` wNEAR from EVM tx 2 remains in the engine's implicit EVM address with no recovery path. User has permanently lost 2 NEAR worth of wNEAR. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** engine-precompiles/src/xcc.rs (L177-216)
```rust
        let required_near =
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
        // if some NEAR payment is needed, transfer it from the caller to the engine's implicit address
        if required_near != ZERO_YOCTO {
            let engine_implicit_address = aurora_engine_sdk::types::near_account_to_evm_address(
                self.engine_account_id.as_bytes(),
            );
            let tx_data = transfer_from_args(
                sender.0.into(),
                engine_implicit_address.raw().0.into(),
                required_near.as_u128().into(),
            );
            let wnear_address = state::get_wnear_address(&self.io);
            let context = aurora_evm::Context {
                address: wnear_address.raw(),
                caller: cross_contract_call::ADDRESS.raw(),
                apparent_value: U256::zero(),
            };
            let (exit_reason, return_value) =
                handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
            match exit_reason {
                // Transfer successful, nothing to do
                aurora_evm::ExitReason::Succeed(_) => (),
                aurora_evm::ExitReason::Revert(r) => {
                    return Err(PrecompileFailure::Revert {
                        exit_status: r,
                        output: return_value,
                    });
                }
                aurora_evm::ExitReason::Error(e) => {
                    return Err(PrecompileFailure::Error { exit_status: e });
                }
                aurora_evm::ExitReason::Fatal(f) => {
                    return Err(PrecompileFailure::Fatal { exit_status: f });
                }
            }
```

**File:** engine-precompiles/src/xcc.rs (L241-255)
```rust
pub mod state {
    //! Functions for reading state related to the cross-contract call feature

    use aurora_engine_sdk::error::ReadU32Error;
    use aurora_engine_sdk::io::{IO, StorageIntermediate};
    use aurora_engine_types::parameters::xcc::CodeVersion;
    use aurora_engine_types::storage::{self, KeyPrefix};
    use aurora_engine_types::types::{Address, Yocto};

    pub const ERR_CORRUPTED_STORAGE: &str = "ERR_CORRUPTED_XCC_STORAGE";
    pub const ERR_MISSING_WNEAR_ADDRESS: &str = "ERR_MISSING_WNEAR_ADDRESS";
    pub const VERSION_KEY: &[u8] = b"version";
    pub const WNEAR_KEY: &[u8] = b"wnear";
    /// Amount of NEAR needed to cover storage for a router contract.
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
```

**File:** engine/src/contract_methods/xcc.rs (L23-65)
```rust
#[named]
pub fn withdraw_wnear_to_router<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
        let args: WithdrawWnearToRouterArgs = io.read_input_borsh()?;
        let current_account_id = env.current_account_id();
        let recipient = AccountId::try_from(format!(
            "{}.{}",
            args.target.encode(),
            current_account_id.as_ref()
        ))?;
        let wnear_address = aurora_engine_precompiles::xcc::state::get_wnear_address(&io);
        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state,
            predecessor_address(&current_account_id),
            current_account_id,
            io,
            env,
        );
        let (result, ids) = xcc::withdraw_wnear_to_router(
            &recipient,
            args.amount,
            wnear_address,
            &mut engine,
            handler,
        )?;
        if !result.status.is_ok() {
            return Err(b"ERR_WITHDRAW_FAILED".into());
        }
        let id = ids.last().ok_or(b"ERR_NO_PROMISE_CREATED")?;
        handler.promise_return(*id);
        Ok(result)
    })
}
```

**File:** engine/src/contract_methods/xcc.rs (L80-99)
```rust
#[named]
pub fn factory_update_address_version<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &H,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        // The function is only set to be private, otherwise callback error will happen.
        env.assert_private_call()?;
        let check_deploy: Result<(), &[u8]> = match handler.promise_result_check() {
            Some(true) => Ok(()),
            Some(false) => Err(b"ERR_ROUTER_DEPLOY_FAILED"),
            None => Err(b"ERR_ROUTER_UPDATE_NOT_CALLBACK"),
        };
        check_deploy?;
        let args: xcc::AddressVersionUpdateArgs = io.read_input_borsh()?;
        xcc::set_code_version_of_address(&mut io, &args.address, args.version);
        Ok(())
    })
```

**File:** engine/src/xcc.rs (L206-282)
```rust
    let latest_code_version = get_latest_code_version(io);
    let sender_code_version = get_code_version_of_address(io, &sender);
    let deploy_needed = AddressVersionStatus::new(io, latest_code_version, sender_code_version);
    // 1. If the router contract account does not exist or is out of date then we start
    //    with a batch transaction to deploy the router. This batch also has an attached
    //    callback to update the engine's storage with the new version of that router account.
    let setup_id = match &deploy_needed {
        AddressVersionStatus::DeployNeeded { create_needed } => {
            let mut promise_actions = Vec::with_capacity(4);
            let code = get_router_code(io).0.into_owned();
            // After the deployment we will call the contract's initialize function
            let wnear_address = get_wnear_address(io);
            let wnear_account = crate::engine::nep141_erc20_map(*io)
                .lookup_right(&crate::engine::ERC20Address(wnear_address))
                .expect("wnear account not found");
            let init_args = format!(
                r#"{{"wnear_account": "{}", "must_register": {}}}"#,
                wnear_account.0.as_ref(),
                create_needed,
            );
            if *create_needed {
                promise_actions.push(PromiseAction::CreateAccount);
                promise_actions.push(PromiseAction::Transfer {
                    amount: STORAGE_AMOUNT,
                });
                promise_actions.push(PromiseAction::DeployContract { code });
                promise_actions.push(PromiseAction::FunctionCall {
                    name: "initialize".into(),
                    args: init_args.into_bytes(),
                    attached_yocto: ZERO_YOCTO,
                    gas: INITIALIZE_GAS,
                });
            } else {
                let deploy_args = DeployUpgradeParams {
                    code,
                    initialize_args: init_args.into_bytes(),
                };
                promise_actions.push(PromiseAction::FunctionCall {
                    name: "deploy_upgrade".into(),
                    args: borsh::to_vec(&deploy_args).expect(ERR_UPGRADE_ARG_SERIALIZATION),
                    attached_yocto: ZERO_YOCTO,
                    gas: UPGRADE_GAS + INITIALIZE_GAS,
                });
            }

            let batch = PromiseBatchAction {
                target_account_id: promise.target_account_id.clone(),
                actions: promise_actions,
            };
            // Safety: This batch creation is safe because it only acts on the router sub-account
            // (not the main engine account), and the actions performed are only (1) create it
            // for the first time and/or (2) deploy the code from our storage (i.e. the deployed
            // code is controlled by us, not the user).
            let promise_id = match base_id {
                Some(id) => handler.promise_attach_batch_callback(id, &batch),
                None => handler.promise_create_batch(&batch),
            };
            // Add a callback here to update the version of the account
            let args = AddressVersionUpdateArgs {
                address: sender,
                version: latest_code_version,
            };
            let callback = PromiseCreateArgs {
                target_account_id: current_account_id.clone(),
                method: "factory_update_address_version".into(),
                args: borsh::to_vec(&args).unwrap(),
                attached_balance: ZERO_YOCTO,
                attached_gas: VERSION_UPDATE_GAS,
            };

            // Safety: A call from the engine to the engine's `factory_update_address_version`
            // method is safe because that method only writes the specific router sub-account
            // metadata that has just been deployed above.
            Some(handler.promise_attach_callback(promise_id, &callback))
        }
        AddressVersionStatus::UpToDate => base_id,
    };
```

**File:** engine/src/xcc.rs (L375-380)
```rust
/// Set the version of the router contract deployed for the given address.
pub fn set_code_version_of_address<I: IO>(io: &mut I, address: &Address, version: CodeVersion) {
    let key = storage::bytes_to_key(KeyPrefix::CrossContractCall, address.as_bytes());
    let value_bytes = version.0.to_le_bytes();
    io.write_storage(&key, &value_bytes);
}
```
