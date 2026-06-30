### Title
XCC Promise Chain Failure Permanently Freezes User wNEAR in Engine's Implicit Address — (`engine-precompiles/src/xcc.rs`, `engine/src/xcc.rs`, `engine/src/contract_methods/xcc.rs`)

---

### Summary

The XCC subsystem commits the user's wNEAR transfer inside the EVM execution phase, then schedules a multi-step NEAR promise chain to deploy the router and unwrap the wNEAR. These two phases are **not atomic**. If the NEAR promise chain fails after the EVM state is committed (e.g., the router deploy batch fails due to a race condition), the user's wNEAR is permanently frozen in the engine's implicit EVM address with no on-chain recovery path.

---

### Finding Description

**Phase 1 — EVM execution (committed atomically):**

When a user calls the XCC precompile for the first time (no router deployed), the precompile computes `required_near = attached_near + STORAGE_AMOUNT` and immediately executes a `transferFrom` inside the EVM to move that wNEAR from the user to the engine's implicit address: [1](#0-0) 

This EVM state change is committed as soon as the outer `submit` call succeeds. The wNEAR is now in the engine's implicit address.

**Phase 2 — NEAR promise chain (scheduled asynchronously):**

`handle_precompile_promise` then schedules a sequential promise chain:

1. **Deploy batch** — `CreateAccount + Transfer(2 NEAR) + DeployContract + Initialize`
2. **`factory_update_address_version`** — records the new router version in engine storage
3. **`withdraw_wnear_to_router`** — unwraps the wNEAR and sends NEAR to the router
4. **`send_refund`** — returns the 2 NEAR storage advance to the engine
5. **`execute`** — runs the user's actual NEAR call [2](#0-1) 

**The failure path:**

`withdraw_wnear_to_router` checks whether the prior promise (`factory_update_address_version`) succeeded and **returns an error immediately** if it did not: [3](#0-2) 

When `withdraw_wnear_to_router` returns an error, the NEAR runtime panics the callback. The wNEAR that was committed in Phase 1 is **never unwrapped** and remains in the engine's implicit address. There is no subsequent callback that attempts to return the wNEAR to the user.

`send_refund` then also panics because it calls `require_no_failed_promises()`: [4](#0-3) [5](#0-4) 

And `execute` panics for the same reason via `assert_preconditions`: [6](#0-5) [7](#0-6) 

**When does the deploy batch fail?**

`get_code_version_of_address` is read during EVM execution (synchronously), before any promises are dispatched: [8](#0-7) 

If two EVM transactions from the same user land in the same NEAR block, both read `None` for the router version and both schedule a deploy batch. The first deploy batch succeeds; the second fails with `CreateAccount` rejected (account already exists). The second user's wNEAR — already committed in Phase 1 — is now frozen.

---

### Impact Explanation

The user's wNEAR (`attached_near + STORAGE_AMOUNT`, i.e. at minimum 2 NEAR worth of wNEAR) is transferred to the engine's implicit EVM address during Phase 1 and is never returned. The engine's implicit address is derived deterministically from the engine's NEAR account ID and is not controllable by any regular EVM user. Recovery requires an admin to manually call the engine and transfer the wNEAR back — there is no on-chain self-service recovery path. This constitutes **temporary (or permanent without admin action) freezing of user funds**.

---

### Likelihood Explanation

The race condition is triggered whenever two XCC calls from the same EVM address are included in the same NEAR block before the first router deploy batch is processed. This is a realistic scenario for any user making rapid sequential XCC calls (e.g., a DeFi contract that fans out multiple XCC calls in one EVM transaction batch, or a user who retries quickly). No malicious actor is required; ordinary usage suffices.

---

### Recommendation

Add a failure-recovery callback at the end of the promise chain that, if any prior step failed, calls back into the engine to return the wNEAR to the originating EVM address. Concretely:

- After the `withdraw_wnear_to_router` step, attach an additional callback that checks `promise_result_check()` and, on failure, executes a wNEAR `transfer` back to the user's EVM address.
- Alternatively, record the pending wNEAR amount in engine storage keyed by the user's address at the time of the EVM transfer, and expose a permissionless `reclaim_stuck_wnear` entry point that the user can call if the promise chain failed.

---

### Proof of Concept

1. User `0xABCD` calls the XCC precompile with `CrossContractCallArgs::Eager(...)` for the first time. `get_code_version_of_address` returns `None`.
2. EVM executes `transferFrom(0xABCD, engine_implicit_addr, attached_near + 2e24)` on the wNEAR ERC-20 — **committed**.
3. User submits a second XCC call in the same NEAR block. `get_code_version_of_address` still returns `None` (deploy batch not yet processed). A second wNEAR transfer is committed.
4. First deploy batch executes: `CreateAccount` succeeds, router `0xABCD.aurora` created.
5. Second deploy batch executes: `CreateAccount` fails (account exists). `factory_update_address_version` sees `promise_result_check() == Some(false)` and returns `ERR_ROUTER_DEPLOY_FAILED`.
6. `withdraw_wnear_to_router` sees `promise_result_check() == Some(false)` at line 33 of `engine/src/contract_methods/xcc.rs` and returns `ERR_CALLBACK_OF_FAILED_PROMISE` — **wNEAR from step 3 is never unwrapped**.
7. `send_refund` panics via `require_no_failed_promises`.
8. `execute` panics via `assert_preconditions` → `require_no_failed_promises`.
9. User's wNEAR from the second call is frozen in the engine's implicit EVM address with no on-chain recovery path.

### Citations

**File:** engine-precompiles/src/xcc.rs (L178-182)
```rust
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
```

**File:** engine-precompiles/src/xcc.rs (L184-216)
```rust
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

**File:** engine/src/xcc.rs (L209-340)
```rust
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

**File:** etc/xcc-router/src/lib.rs (L128-133)
```rust
    pub fn execute(&self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }
```

**File:** etc/xcc-router/src/lib.rs (L176-184)
```rust
    pub fn send_refund(&self) -> Promise {
        let parent = self.get_parent().unwrap_or_else(env_panic);

        require_caller(&parent)
            .and_then(|_| require_no_failed_promises())
            .unwrap_or_else(env_panic);

        Promise::new(parent).transfer(REFUND_AMOUNT)
    }
```

**File:** etc/xcc-router/src/lib.rs (L198-208)
```rust
    fn require_preconditions(&self) -> Result<(), Error> {
        let parent = self.get_parent()?;
        require_caller(&parent)?;
        require_no_failed_promises()?;
        Ok(())
    }

    /// Panics if any of the preconditions checked in `require_preconditions` are not met.
    fn assert_preconditions(&self) {
        self.require_preconditions().unwrap_or_else(env_panic);
    }
```

**File:** etc/xcc-router/src/lib.rs (L382-394)
```rust
fn require_no_failed_promises() -> Result<(), Error> {
    let num_promises = env::promise_results_count();
    for index in 0..num_promises {
        // We can use deprecated `promise_result` rather than `promise_result_checked` safely here,
        // because the promise result could be received from the Aurora Engine itself,
        // and we can be sure that the len of the promise result is within bounds.
        #[allow(deprecated)]
        if env::promise_result(index) == PromiseResult::Failed {
            return Err(Error::CallbackOfFailedPromise);
        }
    }
    Ok(())
}
```
