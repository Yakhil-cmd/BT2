Let me look at the promise handling and the `handle_precompile_promise` flow more carefully to understand the full promise chain.

### Title
XCC Precompile TOCTOU Double-Charge of `STORAGE_AMOUNT` wNEAR Permanently Locks User Funds — (`engine-precompiles/src/xcc.rs`)

---

### Summary

The XCC precompile reads `get_code_version_of_address` synchronously during EVM execution to decide whether to charge `STORAGE_AMOUNT` wNEAR for router deployment. The version key is only written back to storage inside the `factory_update_address_version` callback, which executes asynchronously in a later NEAR block. Two NEAR transactions from the same EVM address that both land before any callback runs will both observe `None`, both charge `STORAGE_AMOUNT`, and both emit deployment promises. The second deployment fails (account already exists), its callback chain aborts, and the second `STORAGE_AMOUNT` wNEAR transferred to the engine's implicit address is never withdrawn to the router — permanently locking 2 NEAR worth of wNEAR with no refund path.

---

### Finding Description

**Check site — `engine-precompiles/src/xcc.rs` lines 177–182:**

```rust
let required_near =
    match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
        // If there is no deployed version of the router contract then we need to charge for storage staking
        None => attached_near + state::STORAGE_AMOUNT,
        Some(_) => attached_near,
    };
``` [1](#0-0) 

This check reads from Aurora's in-contract storage. The corresponding write only happens inside `factory_update_address_version`:

```rust
xcc::set_code_version_of_address(&mut io, &args.address, args.version);
``` [2](#0-1) 

That callback is attached to the deployment promise chain in `handle_precompile_promise`:

```rust
Some(handler.promise_attach_callback(promise_id, &callback))
``` [3](#0-2) 

Callbacks in NEAR execute in a subsequent block — never in the same block as the originating transaction. There is no reservation, lock, or pending-deploy flag written to storage before the callback completes.

**Race window:**

| Block | Event |
|---|---|
| N | NEAR tx1 executes → EVM → XCC precompile → `get_code_version_of_address` = `None` → `transferFrom` STORAGE_AMOUNT wNEAR to engine implicit addr → promise log emitted |
| N | NEAR tx2 executes (same block) → EVM → XCC precompile → `get_code_version_of_address` = `None` (callback not yet run) → `transferFrom` STORAGE_AMOUNT wNEAR again → second promise log emitted |
| N+1 | tx1 deployment batch: `CreateAccount` + `Transfer` + `DeployContract` + `initialize` → succeeds |
| N+1 | tx1 `factory_update_address_version` callback → `Some(true)` → version written |
| N+1 | tx2 deployment batch: `CreateAccount` → **fails** (account already exists) → entire batch fails |
| N+1 | tx2 `factory_update_address_version` callback → `Some(false)` → returns `Err(b"ERR_ROUTER_DEPLOY_FAILED")` → version NOT written |
| N+1 | tx2 `withdraw_wnear_to_router` callback → `promise_result_check()` = `Some(false)` → returns `Err(b"ERR_CALLBACK_OF_FAILED_PROMISE")` → wNEAR NOT withdrawn | [4](#0-3) [5](#0-4) 

The `STORAGE_AMOUNT` wNEAR transferred in tx2 now sits in the engine's implicit EVM address with no automatic refund path back to the user. [6](#0-5) 

`STORAGE_AMOUNT` is 2 NEAR (2 × 10²⁴ yoctoNEAR): [7](#0-6) 

---

### Impact Explanation

The user loses `STORAGE_AMOUNT` wNEAR (2 NEAR) permanently. The wNEAR is held in the engine's implicit EVM address after the failed promise chain. There is no on-chain refund mechanism: `send_refund` is only called from the router back to the engine (to recover the NEAR the engine fronted for storage staking), not from the engine back to the user. [8](#0-7) 

The engine's implicit address accumulates wNEAR that has no corresponding deployed router, violating the invariant that every `STORAGE_AMOUNT` charge corresponds to exactly one router deployment. This is **Critical — Permanent freezing of funds / Insolvency**.

---

### Likelihood Explanation

The race window is any two NEAR transactions from the same EVM address that both reach the Aurora engine contract within the same NEAR block. This is realistic in several scenarios:

- A user submitting two XCC calls in rapid succession (common in DeFi automation)
- A relayer batching multiple EVM transactions from the same address
- Any wallet or SDK that does not wait for callback finality before submitting a second XCC transaction

No special privilege is required. Any unprivileged EVM caller can trigger this by submitting two XCC transactions before the first callback completes.

---

### Recommendation

Before transferring `STORAGE_AMOUNT` wNEAR, write a "pending deploy" sentinel to the address's version slot in storage (e.g., a reserved `CodeVersion` value such as `u32::MAX`). `get_code_version_of_address` should treat this sentinel as "deploy already in flight — do not charge again." The `factory_update_address_version` callback then overwrites the sentinel with the real version on success, or clears it on failure (allowing a retry). This closes the TOCTOU window by making the check-and-reserve atomic within the EVM execution of the first transaction.

---

### Proof of Concept

```rust
// Integration test outline (local sandbox, unmodified engine code)
//
// 1. Deploy Aurora engine with XCC support and wNEAR configured.
// 2. Fund EVM address A with 4 NEAR worth of wNEAR (2× STORAGE_AMOUNT).
// 3. Submit NEAR tx1: EVM tx from address A invoking XCC precompile (Eager call).
// 4. Submit NEAR tx2: EVM tx from address A invoking XCC precompile (Eager call, nonce+1).
//    Both tx1 and tx2 must land in the same NEAR block before any callback runs.
// 5. Wait for all callbacks to settle (2+ blocks).
// 6. Assert:
//    a. Exactly one router account `{A}.aurora` exists on NEAR.
//    b. Address A's wNEAR balance decreased by 2× STORAGE_AMOUNT (not 1×).
//    c. Engine implicit address wNEAR balance increased by STORAGE_AMOUNT
//       (the second charge, never withdrawn).
//    d. No refund was issued to address A.
//
// Expected: assertion (b) and (c) pass, confirming the double-charge and permanent lock.
``` [9](#0-8) [10](#0-9)

### Citations

**File:** engine-precompiles/src/xcc.rs (L177-217)
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
        }
```

**File:** engine-precompiles/src/xcc.rs (L255-255)
```rust
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
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

**File:** engine/src/contract_methods/xcc.rs (L96-98)
```rust
        let args: xcc::AddressVersionUpdateArgs = io.read_input_borsh()?;
        xcc::set_code_version_of_address(&mut io, &args.address, args.version);
        Ok(())
```

**File:** engine/src/xcc.rs (L206-280)
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
