### Title
`execute_scheduled` Accepts NEAR Deposits With No Withdrawal Path — (`etc/xcc-router/src/lib.rs`)

---

### Summary

The `execute_scheduled` function in the XCC router contract is marked `#[payable]` but never uses the attached deposit. Any NEAR sent to this function is silently absorbed into the router's balance. The router has no general withdrawal function, and its only fund-return mechanism sends a fixed constant amount to the parent — not to the original depositor.

---

### Finding Description

`execute_scheduled` at line 149–156 of `etc/xcc-router/src/lib.rs` carries the `#[payable]` attribute, which in the NEAR SDK means the function accepts attached NEAR without panicking. However, the function body never reads `env::attached_deposit()` — it only removes a scheduled promise from storage and executes it. [1](#0-0) 

The attached NEAR is silently absorbed into the router contract's balance. The router exposes no general withdrawal function. Its only fund-return path is `send_refund`, which unconditionally transfers a hardcoded constant `REFUND_AMOUNT` (2 NEAR) to the parent account — not to the original caller, and not for an arbitrary amount. [2](#0-1) 

The constant is defined as: [3](#0-2) 

The comment on `execute_scheduled` explicitly states the function is intentionally open to any caller: [4](#0-3) 

This means any external account — not just the Aurora Engine parent — can call `execute_scheduled` with attached NEAR. Because the function is `#[payable]`, the NEAR is accepted without error. Because the router has no withdrawal function, those funds have no direct recovery path for the depositor.

A secondary instance of the same class exists in `fund_xcc_sub_account` (`engine/src/xcc.rs`). When an upgrade is needed (`create_needed = false`), the full `fund_amount` from `env.attached_deposit()` is forwarded to the router's `deploy_upgrade` call: [5](#0-4) 

`deploy_upgrade` is also `#[payable]`: [6](#0-5) 

If the inner batch (deploy + initialize) fails after `deploy_upgrade` itself returns successfully, the `fund_amount` stays in the router's balance. The only callback attached is `factory_update_address_version`, which detects the failure but issues no refund: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

Any NEAR attached to `execute_scheduled` is locked in the router contract with no direct recovery path for the sender. The only recovery avenue is for the Aurora Engine owner to upgrade the router to add a withdrawal function — an out-of-band administrative action. This constitutes **temporary freezing of user funds (High)**.

---

### Likelihood Explanation

`execute_scheduled` is intentionally callable by any account. The `#[payable]` annotation signals to callers and tooling that deposits are accepted, increasing the probability of accidental or UI-driven deposits. A user executing a scheduled promise may attach NEAR expecting it to be forwarded to the promise (e.g., for storage or gas). The `fund_xcc_sub_account` path is triggered whenever a router upgrade is pending and the upgrade batch fails — a realistic scenario after a `factory_update` that introduces a bug in the router's `initialize` logic.

---

### Recommendation

1. **Remove `#[payable]` from `execute_scheduled`** if no deposit is required. Without the attribute, any attached NEAR will cause the call to panic and be automatically refunded by the NEAR runtime.
2. If deposits are intentionally accepted to be forwarded to the scheduled promise, add explicit logic to read `env::attached_deposit()` and attach it to the promise creation.
3. For the `fund_xcc_sub_account` upgrade path, add a failure callback that refunds `fund_amount` to the original caller when the `deploy_upgrade` batch fails.

---

### Proof of Concept

**`execute_scheduled` path:**

1. Deploy the Aurora Engine with XCC support; a router sub-account is created for a user address.
2. The parent engine calls `schedule` on the router, storing a promise at nonce `N`.
3. Any external account calls `execute_scheduled(N)` with 1 NEAR attached.
4. The NEAR SDK accepts the deposit (no panic) because of `#[payable]`; the 1 NEAR is absorbed into the router's balance.
5. The caller has no mechanism to recover the 1 NEAR. `send_refund` sends a fixed 2 NEAR only to the parent engine account, not to the depositor.

**`fund_xcc_sub_account` upgrade path:**

1. Engine owner calls `factory_update` with new (buggy) router bytecode.
2. User calls `fund_xcc_sub_account` (with `wnear_account_id = None`, so no owner restriction) attaching 3 NEAR.
3. `fund_xcc_sub_account` detects `create_needed = false`, forwards 3 NEAR to `deploy_upgrade` on the router.
4. `deploy_upgrade` succeeds (schedules the batch), consuming the 3 NEAR into the router's balance.
5. The inner batch (deploy + initialize) fails because the new bytecode's `initialize` panics.
6. `factory_update_address_version` callback fires, detects failure, returns `ERR_ROUTER_DEPLOY_FAILED` — but issues no refund.
7. The user's 3 NEAR is locked in the router with no recovery path. [1](#0-0) [6](#0-5) [9](#0-8) [8](#0-7)

### Citations

**File:** etc/xcc-router/src/lib.rs (L40-40)
```rust
const REFUND_AMOUNT: NearToken = NearToken::from_near(2);
```

**File:** etc/xcc-router/src/lib.rs (L146-148)
```rust
    /// It is intentional that this function can be called by anyone (not just the parent).
    /// There is no security risk to allowing this function to be open because it can only
    /// act on promises that were created via `schedule`.
```

**File:** etc/xcc-router/src/lib.rs (L149-156)
```rust
    #[payable]
    pub fn execute_scheduled(&mut self, nonce: U64) {
        let Some(promise) = self.scheduled_promises.remove(&nonce.0) else {
            env::panic_str("ERR_PROMISE_NOT_FOUND")
        };
        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }
```

**File:** etc/xcc-router/src/lib.rs (L160-174)
```rust
    #[payable]
    pub fn deploy_upgrade(&mut self, #[serializer(borsh)] args: DeployUpgradeParams) {
        self.assert_preconditions();

        let promise_id = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_contract(promise_id, &args.code);
        env::promise_batch_action_function_call(
            promise_id,
            INITIALIZE,
            &args.initialize_args,
            NearToken::default(),
            INITIALIZE_GAS,
        );
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

**File:** engine/src/xcc.rs (L90-148)
```rust
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
```

**File:** engine/src/xcc.rs (L157-173)
```rust
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
