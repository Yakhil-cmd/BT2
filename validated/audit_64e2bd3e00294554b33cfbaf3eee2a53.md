### Title
Concurrent XCC Precompile Calls for the Same New EVM Address Cause Double STORAGE_AMOUNT Drain from the Engine - (File: engine/src/xcc.rs)

### Summary

When two EVM transactions from the same EVM address invoke the XCC precompile in the same NEAR block (or in rapid succession before the first `factory_update_address_version` callback settles), both transactions observe `get_code_version_of_address` returning `None` and independently schedule a `CreateAccount + Transfer(STORAGE_AMOUNT) + DeployContract + initialize` batch against the same router sub-account. The engine pays `STORAGE_AMOUNT` (2 NEAR) twice, but the second `CreateAccount` action fails silently on-chain (NEAR ignores duplicate account creation in a batch), so the second transfer of 2 NEAR is lost from the engine's balance with no refund path.

### Finding Description

The XCC precompile flow works as follows:

1. An EVM contract calls the XCC precompile (`engine-precompiles/src/xcc.rs`). The precompile checks whether the caller's router sub-account exists by reading `get_code_version_of_address`. If `None`, it charges the caller an extra `STORAGE_AMOUNT` (2 NEAR) in wNEAR via an EVM-level `transferFrom`.
2. After EVM execution, `filter_promises_from_logs` in `engine/src/engine.rs` calls `handle_precompile_promise` in `engine/src/xcc.rs`.
3. `handle_precompile_promise` again reads `get_code_version_of_address` from the engine's on-chain storage. If `None`, it schedules a NEAR batch: `[CreateAccount, Transfer(STORAGE_AMOUNT), DeployContract, initialize]` targeting the router sub-account, followed by a `factory_update_address_version` callback that writes the version into storage.

The critical race: the version is only written to storage **after** the async `factory_update_address_version` callback completes. If two EVM transactions for the same EVM address are included in the same NEAR block (or in consecutive blocks before the callback settles), both calls to `get_code_version_of_address` return `None`, both charge the user `STORAGE_AMOUNT` in wNEAR, and both schedule a `CreateAccount + Transfer(STORAGE_AMOUNT)` batch against the same router sub-account.

The second `CreateAccount` action silently fails on NEAR (the account already exists), but the `Transfer(STORAGE_AMOUNT)` action in the same batch still executes, sending another 2 NEAR from the engine to the already-created router account. The engine has no mechanism to recover this second 2 NEAR payment.

**Root cause code path:**

- `engine-precompiles/src/xcc.rs` lines 177–182: checks `get_code_version_of_address` and charges `STORAGE_AMOUNT` if `None`.
- `engine/src/xcc.rs` lines 206–208: `handle_precompile_promise` again reads `get_code_version_of_address` from storage (still `None` for the second concurrent tx).
- `engine/src/xcc.rs` lines 226–237: schedules `CreateAccount + Transfer(STORAGE_AMOUNT) + DeployContract + initialize`.
- `engine/src/contract_methods/xcc.rs` lines 90–97: `factory_update_address_version` only writes the version after the batch succeeds — too late to prevent the race. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation

Each successful exploit drains `STORAGE_AMOUNT` = 2 NEAR from the engine contract's balance with no refund. The engine's NEAR balance is a shared resource that backs all XCC storage staking. Repeated exploitation across many addresses (or the same address across many blocks before the callback lands) can progressively drain the engine's NEAR balance, eventually causing insolvency of the engine's NEAR-side funds and breaking XCC for all users. This is a **High** impact: temporary or progressive fund freeze / theft of engine-held NEAR. [5](#0-4) [6](#0-5) 

### Likelihood Explanation

Any unprivileged EVM user can trigger this by submitting two EVM transactions from the same address to the XCC precompile in the same NEAR block (NEAR processes multiple receipts per block). The attacker pays wNEAR for both calls (the EVM-level `transferFrom` succeeds for both), but the engine pays 2 NEAR twice. The attacker recovers their wNEAR cost via the router account's extra balance. This is straightforward to execute with no special privileges. [7](#0-6) [8](#0-7) 

### Recommendation

**Short term:** Before scheduling the `CreateAccount` batch in `handle_precompile_promise`, write a sentinel/pending marker for the address into engine storage (e.g., a `PendingDeploy` version flag). Subsequent concurrent calls that see this marker should skip the `CreateAccount + Transfer` batch and proceed as if the account already exists (or revert). The `factory_update_address_version` callback then replaces the sentinel with the real version.

**Long term:** Introduce an idempotency check: if `CreateAccount` fails in the batch (NEAR already has the account), the `Transfer(STORAGE_AMOUNT)` action in the same batch should be skipped or the excess NEAR should be refunded back to the engine. Alternatively, use a two-phase commit pattern where the engine marks an address as "deploy in progress" atomically before scheduling any NEAR promises. [9](#0-8) [10](#0-9) 

### Proof of Concept

1. Alice (EVM address `0xALICE`) has wNEAR approved to the XCC precompile. No router sub-account exists yet (`get_code_version_of_address` returns `None`).
2. Alice submits two EVM transactions (Tx1 and Tx2) to the XCC precompile in the same NEAR block.
3. Both Tx1 and Tx2 execute within the same NEAR block. At EVM execution time for both, `get_code_version_of_address(&self.io, &Address::new(sender))` returns `None` (line 178 of `engine-precompiles/src/xcc.rs`), so both charge Alice `attached_near + STORAGE_AMOUNT`.
4. Both EVM executions succeed and emit XCC logs. `filter_promises_from_logs` calls `handle_precompile_promise` for both.
5. For both calls, `get_code_version_of_address(io, &sender)` at line 207 of `engine/src/xcc.rs` still returns `None` (the `factory_update_address_version` callback from Tx1 has not yet executed).
6. Both calls schedule `[CreateAccount, Transfer(2 NEAR), DeployContract, initialize]` targeting `0xALICE.aurora`.
7. Tx1's batch succeeds: router account created, 2 NEAR transferred from engine.
8. Tx2's batch executes: `CreateAccount` silently fails (account exists), but `Transfer(2 NEAR)` still executes — another 2 NEAR leaves the engine with no refund.
9. Net result: engine loses 2 NEAR permanently. Alice's router account has 4 NEAR instead of 2 NEAR. [11](#0-10) [12](#0-11)

### Citations

**File:** engine-precompiles/src/xcc.rs (L177-182)
```rust
        let required_near =
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
```

**File:** engine-precompiles/src/xcc.rs (L254-255)
```rust
    /// Amount of NEAR needed to cover storage for a router contract.
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
```

**File:** engine/src/xcc.rs (L68-88)
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

**File:** engine/src/xcc.rs (L206-262)
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
```

**File:** engine/src/xcc.rs (L453-475)
```rust
impl AddressVersionStatus {
    fn new<I: IO>(
        io: &I,
        latest_code_version: CodeVersion,
        target_code_version: Option<CodeVersion>,
    ) -> Self {
        let first_upgradable_version =
            get_first_upgradable_version(io).unwrap_or(CodeVersion::ZERO);
        match target_code_version {
            None => Self::DeployNeeded {
                create_needed: true,
            },
            Some(version) if version < first_upgradable_version => {
                // It is impossible to upgrade the initial XCC routers because
                // they lack the upgrade method.
                Self::UpToDate
            }
            Some(version) if version < latest_code_version => Self::DeployNeeded {
                create_needed: false,
            },
            Some(_version) => Self::UpToDate,
        }
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

**File:** engine/src/engine.rs (L1692-1710)
```rust
            } else if log.address == cross_contract_call::ADDRESS.raw() {
                if log.topics[0] == cross_contract_call::AMOUNT_TOPIC {
                    // NEAR balances are 128-bit, so the leading 16 bytes of the 256-bit topic
                    // value should always be zero.
                    assert_eq!(&log.topics[1].as_bytes()[0..16], &[0; 16]);
                    let required_near =
                        Yocto::new(U256::from_big_endian(log.topics[1].as_bytes()).low_u128());
                    if let Ok(promise) = PromiseCreateArgs::try_from_slice(&log.data) {
                        let id = crate::xcc::handle_precompile_promise(
                            io,
                            handler,
                            previous_promise,
                            &promise,
                            required_near,
                            current_account_id,
                        );
                        previous_promise = Some(id);
                    }
                }
```
