### Title
XCC Precompile Router Deployment TOCTOU Freezes User wNEAR Funds - (`engine-precompiles/src/xcc.rs`)

### Summary

The XCC precompile checks whether a user's router contract is deployed by reading `get_code_version_of_address` from storage at EVM execution time. The router deployment itself happens asynchronously via NEAR promises in a later block. If a user submits two XCC transactions in the same NEAR block before their router is deployed, both transactions charge `STORAGE_AMOUNT` (2 NEAR) in wNEAR, but only one router deployment succeeds. The second deployment fails because the account already exists, causing the `withdraw_wnear_to_router` callback to abort, permanently stranding the user's wNEAR in the engine's implicit EVM address with no automatic refund path.

### Finding Description

**Root cause — check phase (`engine-precompiles/src/xcc.rs`):**

The precompile reads the router deployment state from storage and computes `required_near`:

```rust
let required_near =
    match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
        None => attached_near + state::STORAGE_AMOUNT,   // 2 NEAR added
        Some(_) => attached_near,
    };
if required_near != ZERO_YOCTO {
    // transferFrom: moves wNEAR from user → engine implicit address (EVM state)
    handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
}
```

This `transferFrom` executes atomically inside the EVM and immediately deducts `required_near` wNEAR from the user's EVM balance. [1](#0-0) 

**Root cause — use phase (`engine/src/xcc.rs`):**

`handle_precompile_promise` also reads `get_code_version_of_address` at EVM execution time and schedules the NEAR promise chain:

```
deploy_batch (CreateAccount + Transfer + DeployContract + initialize)
  → factory_update_address_version   (updates code version in storage)
    → withdraw_wnear_to_router        (moves wNEAR from engine implicit → router)
      → user_call
```

The code version in storage is only updated when `factory_update_address_version` executes — asynchronously, in a later NEAR block. [2](#0-1) 

**Failure path — `withdraw_wnear_to_router` abort:**

`withdraw_wnear_to_router` checks whether its predecessor promise succeeded:

```rust
if matches!(handler.promise_result_check(), Some(false)) {
    return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
}
```

If the deploy batch fails, `factory_update_address_version` returns `ERR_ROUTER_DEPLOY_FAILED`, which causes `withdraw_wnear_to_router` to abort without executing the wNEAR exit. [3](#0-2) 

**`factory_update_address_version` failure on deploy failure:**

```rust
let check_deploy: Result<(), &[u8]> = match handler.promise_result_check() {
    Some(true) => Ok(()),
    Some(false) => Err(b"ERR_ROUTER_DEPLOY_FAILED"),
    None => Err(b"ERR_ROUTER_UPDATE_NOT_CALLBACK"),
};
check_deploy?;
``` [4](#0-3) 

**`STORAGE_AMOUNT` constant:**

```rust
pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
``` [5](#0-4) 

### Proof of Concept

1. User Alice has never used XCC (no router deployed). She holds ≥ 4 NEAR worth of wNEAR ERC-20 and has approved the XCC precompile to spend it.
2. Alice submits two XCC transactions (nonce N and N+1) in rapid succession; both land in the same NEAR block.
3. **Block N — EVM tx 1 executes:**
   - `get_code_version_of_address(alice)` → `None`
   - `required_near = STORAGE_AMOUNT` (2 NEAR)
   - `transferFrom` moves 2 NEAR wNEAR from Alice → engine implicit address ✓
   - Promise chain scheduled: `deploy_batch → factory_update_address_version → withdraw_wnear_to_router → call`
4. **Block N — EVM tx 2 executes (code version still `None` in storage):**
   - `get_code_version_of_address(alice)` → `None` (promise hasn't run yet)
   - `required_near = STORAGE_AMOUNT` (2 NEAR)
   - `transferFrom` moves another 2 NEAR wNEAR from Alice → engine implicit address ✓
   - Second promise chain scheduled: `deploy_batch → factory_update_address_version → withdraw_wnear_to_router → call`
5. **Block N+1 — Promise chain 1 executes:**
   - `CreateAccount` succeeds → router deployed → `factory_update_address_version` updates code version → `withdraw_wnear_to_router` moves 2 NEAR wNEAR to router ✓
6. **Block N+1 — Promise chain 2 executes:**
   - `CreateAccount` **fails** (router account already exists) → entire deploy batch fails
   - `factory_update_address_version` receives `Some(false)` → returns `ERR_ROUTER_DEPLOY_FAILED`
   - `withdraw_wnear_to_router` receives `Some(false)` → returns `ERR_CALLBACK_OF_FAILED_PROMISE` without executing
   - **Alice's 2 NEAR wNEAR remains stranded in the engine's implicit EVM address with no automatic refund.**

The engine's implicit address (`near_account_to_evm_address(engine_account_id)`) is not controlled by any private key and has no admin recovery function exposed in the contract. [6](#0-5) 

### Impact Explanation

**High — Temporary/permanent freezing of user funds.**

Each occurrence strands `STORAGE_AMOUNT` = 2 NEAR worth of wNEAR ERC-20 tokens in the engine's implicit EVM address. There is no automatic refund path in the contract. Recovery requires admin intervention (engine upgrade or a new privileged method). The user's XCC call also fails, so they lose both the funds and the intended cross-contract call.

### Likelihood Explanation

**Medium.** The preconditions are:
- User is making their first XCC call (no router deployed yet — common for new users).
- Two XCC transactions from the same user land in the same NEAR block (~1 second window). This happens naturally when a user submits transactions in quick succession or uses a batching relayer.
- User holds ≥ 4 NEAR worth of wNEAR (reasonable for XCC users).

No privileged access is required. The user triggers this inadvertently through normal usage patterns.

### Recommendation

Track in-flight router deployments using a storage flag (e.g., `pending_deploy: Set<Address>`) set atomically during EVM execution and cleared in the `factory_update_address_version` callback. Before charging `STORAGE_AMOUNT`, check both `get_code_version_of_address` and the pending-deploy flag:

```rust
let required_near = match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
    None if !state::is_deploy_pending(&self.io, &Address::new(sender)) => {
        state::set_deploy_pending(&mut self.io, &Address::new(sender));
        attached_near + state::STORAGE_AMOUNT
    }
    _ => attached_near,
};
```

This mirrors the mitigation suggested for MagicSpend: use a tracked state variable rather than a live balance/existence check that does not account for concurrent in-flight operations.

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

**File:** engine-precompiles/src/xcc.rs (L255-255)
```rust
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
```

**File:** engine/src/xcc.rs (L206-340)
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
    // 2. If some NEAR is required for this call (from storage staking for a new account
    //    and/or attached NEAR to the call the user wants to make), then we need to have the
    //    engine withdraw that amount of wNEAR to the router account and then have the router
    //    unwrap it into actual NEAR. In the case of storage staking, the engine contract
    //    covered the cost initially (see setup batch above), so the unwrapping also sends
    //    a refund back to the engine.
    let withdraw_id = if required_near == ZERO_YOCTO {
        setup_id
    } else {
        let withdraw_call_args = WithdrawWnearToRouterArgs {
            target: sender,
            amount: required_near,
        };
        let withdraw_call = PromiseCreateArgs {
            target_account_id: current_account_id.clone(),
            method: "withdraw_wnear_to_router".into(),
            args: borsh::to_vec(&withdraw_call_args).unwrap(),
            attached_balance: ZERO_YOCTO,
            attached_gas: WITHDRAW_GAS,
        };
        // Safety: This promise is safe. Even though this is a call from the engine account to
        // itself invoking the `call` method (which could be dangerous), the argument to `call`
        // is controlled entirely by us (not any user). This call will only execute the wnear
        // exit precompile, and only for the necessary amount. Note that this amount will always
        // be present, otherwise the user's call to the xcc precompile would have failed.
        let id = match setup_id {
            None => handler.promise_create_call(&withdraw_call),
            Some(setup_id) => handler.promise_attach_callback(setup_id, &withdraw_call),
        };
        let refund_needed = match deploy_needed {
            AddressVersionStatus::DeployNeeded { create_needed } => create_needed,
            AddressVersionStatus::UpToDate => false,
        };
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
            Some(id)
        }
    };
    // 3. Finally we can do the call the user wanted to do.

    // Safety: this call is safe because the promise comes from the XCC precompile, not the
    // user directly. The XCC precompile will only construct promises that target the `execute`
    // and `schedule` methods of the user's router contract. Therefore, the user cannot have
    // the engine make arbitrary calls.
    match withdraw_id {
        None => handler.promise_create_call(promise),
        Some(withdraw_id) => handler.promise_attach_callback(withdraw_id, promise),
    }
```

**File:** engine/src/contract_methods/xcc.rs (L33-35)
```rust
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
```

**File:** engine/src/contract_methods/xcc.rs (L90-95)
```rust
        let check_deploy: Result<(), &[u8]> = match handler.promise_result_check() {
            Some(true) => Ok(()),
            Some(false) => Err(b"ERR_ROUTER_DEPLOY_FAILED"),
            None => Err(b"ERR_ROUTER_UPDATE_NOT_CALLBACK"),
        };
        check_deploy?;
```
