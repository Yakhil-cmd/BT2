### Title
Missing Minimum `attached_gas` Validation in XCC Precompile Allows Permanent Freezing of User wNEAR - (File: engine-precompiles/src/xcc.rs)

### Summary
The Cross-Contract Call (XCC) precompile accepts user-supplied `PromiseCreateArgs` containing `attached_gas` and `attached_balance` fields without validating that `attached_gas` is non-zero when `attached_balance > 0`. An EVM user who specifies a non-zero NEAR balance but zero gas for their XCC promise will have their wNEAR permanently frozen in the XCC router sub-account, with no recovery path.

### Finding Description

The XCC precompile at `engine-precompiles/src/xcc.rs` processes `CrossContractCallArgs` submitted by any EVM user. For the `Eager` variant, it extracts `call_gas = call.total_gas()` and `attached_near = call.total_near()` from the user-supplied `PromiseArgs`, then constructs the router call:

```rust
CrossContractCallArgs::Eager(call) => {
    let call_gas = call.total_gas();
    let attached_near = call.total_near();
    ...
    let promise = PromiseCreateArgs {
        ...
        attached_gas: router_exec_cost.saturating_add(call_gas),
    };
    (promise, attached_near)
}
``` [1](#0-0) 

There is no check that `call_gas > 0` when `attached_near > 0`. The EVM gas cost for the gas portion is computed as:

```rust
cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
``` [2](#0-1) 

When `call_gas = 0`, this adds zero EVM gas cost, so the user pays no penalty for specifying zero gas. The precompile then proceeds to transfer wNEAR from the user to the engine's implicit address when `required_near != ZERO_YOCTO`: [3](#0-2) 

The wNEAR is burned (unwrapped to NEAR) and forwarded to the router sub-account via `withdraw_wnear_to_router`. The router then executes the user's promise via `base_promise_create`, which passes `attached_gas = 0` directly to `env::promise_create`:

```rust
fn base_promise_create(promise: &PromiseCreateArgs) -> PromiseIndex {
    env::promise_create(
        ...
        NearToken::from_yoctonear(promise.attached_balance.as_u128()),
        Gas::from_gas(promise.attached_gas.as_u64()),  // 0 gas
    )
}
``` [4](#0-3) 

A NEAR promise with 0 gas fails immediately. On failure, NEAR refunds the attached NEAR balance to the predecessor — the router sub-account. The router has no `withdraw` or user-recovery function for this case; only `send_refund` exists, which is exclusively for storage-staking refunds back to the engine: [5](#0-4) 

The same issue applies to `CrossContractCallArgs::Delayed`: the promise is stored in the router with `attached_gas = 0`, the user's wNEAR is transferred to the router, and when `execute_scheduled` is called, the promise fails and the NEAR is stuck in the router. [6](#0-5) 

The `PromiseCreateArgs` struct itself imposes no constraints on `attached_gas`: [7](#0-6) 

### Impact Explanation

**Critical — Permanent freezing of funds.**

A user who calls the XCC precompile with `attached_balance > 0` and `attached_gas = 0` will have their wNEAR permanently frozen. The sequence is:

1. User's wNEAR is burned via `transferFrom` on the wNEAR ERC-20 contract (irreversible EVM state change).
2. The equivalent NEAR is forwarded to the router sub-account.
3. The router calls the target contract with 0 gas; the call fails.
4. NEAR is refunded to the router (not the user).
5. The router has no user-accessible recovery function.

The user's wNEAR is gone and the NEAR is permanently locked in the router sub-account.

### Likelihood Explanation

**Low.** This requires a user to misconfigure their XCC call by specifying `attached_gas = 0` alongside a non-zero `attached_balance`. This is analogous to the original report's "user error/misconfiguration" likelihood. However, the XCC interface accepts raw Borsh-encoded `PromiseArgs`, making it easy to accidentally omit or zero-out the gas field, especially when constructing calls programmatically.

### Recommendation

Add a validation check in the XCC precompile that rejects any `CrossContractCallArgs` where `attached_near > 0` but `total_gas() == 0`. Additionally, enforce a minimum gas value (e.g., at least 1 Tgas per promise) to ensure the target contract can execute. The check should be applied before any wNEAR transfer occurs:

```rust
if attached_near != ZERO_YOCTO && call_gas == NearGas::new(0) {
    return Err(revert_with_message("ERR_ZERO_GAS_WITH_NEAR_ATTACHED"));
}
```

Similarly, the router's `execute` and `execute_scheduled` functions should validate that each `PromiseCreateArgs` has a non-zero `attached_gas` before executing.

### Proof of Concept

1. Deploy a contract on Aurora that approves the XCC precompile to spend wNEAR.
2. Call the XCC precompile with:
   ```
   CrossContractCallArgs::Eager(PromiseArgs::Create(PromiseCreateArgs {
       target_account_id: "some.near",
       method: "some_method",
       args: vec![],
       attached_balance: Yocto::new(1_000_000_000_000_000_000_000_000), // 1 NEAR
       attached_gas: NearGas::new(0), // zero gas
   }))
   ```
3. Observe that the EVM gas cost for the gas portion is 0 (no penalty for zero gas).
4. Observe that the user's wNEAR is burned via `transferFrom`.
5. Observe that the router sub-account receives 1 NEAR.
6. Observe that the router's call to `some.near` fails with out-of-gas.
7. Observe that the 1 NEAR is refunded to the router sub-account.
8. Confirm the user cannot recover the NEAR — the router has no user-facing withdrawal function for this case. [8](#0-7) [9](#0-8)

### Citations

**File:** engine-precompiles/src/xcc.rs (L99-175)
```rust
impl<I: IO> HandleBasedPrecompile for CrossContractCall<I> {
    #[allow(clippy::too_many_lines)]
    fn run_with_handle(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Result<PrecompileOutput, PrecompileFailure> {
        let input = handle.input();
        let target_gas = handle.gas_limit().map(EthGas::new);
        let context = handle.context();
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
        let is_static = handle.is_static();

        // This only includes the cost we can easily derive without parsing the input.
        // This allows failing fast without wasting computation on parsing.
        let input_len = u64::try_from(input.len()).map_err(utils::err_usize_conv)?;
        let mut cost =
            costs::CROSS_CONTRACT_CALL_BASE + costs::CROSS_CONTRACT_CALL_BYTE * input_len;
        let check_cost = |cost: EthGas| -> Result<(), PrecompileFailure> {
            if let Some(target_gas) = target_gas
                && cost > target_gas
            {
                return Err(PrecompileFailure::Error {
                    exit_status: ExitError::OutOfGas,
                });
            }
            Ok(())
        };
        check_cost(cost)?;

        // It's not allowed to call cross contract call precompile in static or delegate mode
        if is_static {
            return Err(revert_with_message(consts::ERR_STATIC));
        } else if context.address != cross_contract_call::ADDRESS.raw() {
            return Err(revert_with_message(consts::ERR_DELEGATE));
        }

        let sender = context.caller;
        let target_account_id = create_target_account_id(sender, self.engine_account_id.as_ref())?;
        let args = CrossContractCallArgs::try_from_slice(input)
            .map_err(|_| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
        let (promise, attached_near) = match args {
            CrossContractCallArgs::Eager(call) => {
                let call_gas = call.total_gas();
                let attached_near = call.total_near();
                let callback_count = call
                    .promise_count()
                    .checked_sub(1)
                    .ok_or_else(|| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
                let router_exec_cost = costs::ROUTER_EXEC_BASE
                    + NearGas::new(callback_count * costs::ROUTER_EXEC_PER_CALLBACK.as_u64());
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_EXEC_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: router_exec_cost.saturating_add(call_gas),
                };
                (promise, attached_near)
            }
            CrossContractCallArgs::Delayed(call) => {
                let attached_near = call.total_near();
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_SCHEDULE_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    // We don't need to add any gas to the amount need for the schedule call
                    // since the promise is not executed right away.
                    attached_gas: costs::ROUTER_SCHEDULE,
                };
                (promise, attached_near)
            }
        };
        cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
        check_cost(cost)?;
```

**File:** engine-precompiles/src/xcc.rs (L177-200)
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
```

**File:** etc/xcc-router/src/lib.rs (L232-240)
```rust
    fn base_promise_create(promise: &PromiseCreateArgs) -> PromiseIndex {
        env::promise_create(
            promise.target_account_id.as_ref().parse().unwrap(),
            promise.method.as_str(),
            &promise.args,
            NearToken::from_yoctonear(promise.attached_balance.as_u128()),
            Gas::from_gas(promise.attached_gas.as_u64()),
        )
    }
```

**File:** engine/src/xcc.rs (L68-176)
```rust
pub fn fund_xcc_sub_account<I, P, E>(
    io: &I,
    handler: &mut P,
    env: &E,
    args: FundXccArgs,
) -> Result<(), FundXccError>
where
    P: PromiseHandler,
    I: IO + Copy,
    E: Env,
{
    let current_account_id = env.current_account_id();
    let target_account_id = AccountId::try_from(format!(
        "{}.{}",
        args.target.encode(),
        current_account_id.as_ref()
    ))?;

    let latest_code_version = get_latest_code_version(io);
    let target_code_version = get_code_version_of_address(io, &args.target);
    let deploy_needed = AddressVersionStatus::new(io, latest_code_version, target_code_version);

    let fund_amount = Yocto::new(env.attached_deposit());

    let mut promise_actions = Vec::with_capacity(4);

    // If account needs to be created and/or updated then include those actions.
    if let AddressVersionStatus::DeployNeeded { create_needed } = deploy_needed {
        let code = get_router_code(io).0.into_owned();
        // wnear_account is needed for initialization so we must assume it is set
        // in the Engine, or we need to accept it as input.
        let wnear_account = if let Some(wnear_account) = args.wnear_account_id {
            wnear_account
        } else {
            // If the wnear account is not specified then we must look it up based on the
            // bridged token registry for the engine.
            let wnear_address = get_wnear_address(io);
            crate::engine::nep141_erc20_map(*io)
                .lookup_right(&crate::engine::ERC20Address(wnear_address))
                .ok_or(FundXccError::MissingWNearAddress)?
                .0
        };
        let init_args = format!(
            r#"{{"wnear_account": "{}", "must_register": {}}}"#,
            wnear_account.as_ref(),
            create_needed,
        );
        if create_needed {
            if fund_amount < STORAGE_AMOUNT {
                return Err(FundXccError::InsufficientBalance);
            }

            promise_actions.push(PromiseAction::CreateAccount);
            promise_actions.push(PromiseAction::Transfer {
                amount: fund_amount,
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
                attached_yocto: fund_amount,
                gas: UPGRADE_GAS + INITIALIZE_GAS,
            });
        }
    } else {
        // No matter what include the transfer of the funding amount
        promise_actions.push(PromiseAction::Transfer {
            amount: fund_amount,
        });
    }

    let batch = PromiseBatchAction {
        target_account_id,
        actions: promise_actions,
    };
    // Safety: same as safety in `handle_precompile_promise`
    let promise_id = handler.promise_create_batch(&batch);

    if let AddressVersionStatus::DeployNeeded { .. } = deploy_needed {
        // If a creation and/or deployment were needed, then we must attach a callback to update
        // the Engine's record of the account.

        let args = AddressVersionUpdateArgs {
            address: args.target,
            version: latest_code_version,
        };
        let callback = PromiseCreateArgs {
            target_account_id: current_account_id,
            method: "factory_update_address_version".into(),
            args: borsh::to_vec(&args).map_err(|_| FundXccError::SerializationFailure)?,
            attached_balance: ZERO_YOCTO,
            attached_gas: VERSION_UPDATE_GAS,
        };
        let _promise_id = handler.promise_attach_callback(promise_id, &callback);
    }

    Ok(())
}
```

**File:** engine/src/xcc.rs (L316-327)
```rust
        if refund_needed {
            let refund_call = PromiseCreateArgs {
                target_account_id: promise.target_account_id.clone(),
                method: "send_refund".into(),
                args: Vec::new(),
                attached_balance: ZERO_YOCTO,
                attached_gas: REFUND_GAS,
            };
            // Safety: This call is safe because the router's `send_refund` method
            // does not violate any security invariants. It only sends NEAR back to this contract.
            Some(handler.promise_attach_callback(id, &refund_call))
        } else {
```

**File:** engine-types/src/parameters/promise.rs (L210-218)
```rust
#[must_use]
#[derive(Debug, BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq)]
pub struct PromiseCreateArgs {
    pub target_account_id: AccountId,
    pub method: String,
    pub args: Vec<u8>,
    pub attached_balance: Yocto,
    pub attached_gas: NearGas,
}
```
