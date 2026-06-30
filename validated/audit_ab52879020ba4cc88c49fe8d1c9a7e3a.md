### Title
Permanent wNEAR Freeze via Multiple XCC Precompile Calls Before Router Deployment — (File: engine-precompiles/src/xcc.rs)

---

### Summary

The `CrossContractCall` precompile (`engine-precompiles/src/xcc.rs`) violates the Checks-Effects-Interactions pattern. It reads the router deployment state, then makes an external EVM sub-call to transfer wNEAR, but the state update (router version) only occurs asynchronously via a NEAR promise callback. When a user makes N XCC precompile calls in a single EVM transaction before their router is deployed, each call independently charges `STORAGE_AMOUNT` (2 NEAR worth of wNEAR) from the user. Only the first promise chain succeeds; subsequent chains fail because the router account already exists. The wNEAR transferred for the failed chains is permanently frozen in the engine's implicit EVM address with no recovery path.

---

### Finding Description

In `run_with_handle` (`engine-precompiles/src/xcc.rs`), the precompile first checks whether the caller's XCC router sub-account exists:

```rust
// Lines 177-182
let required_near =
    match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
        None => attached_near + state::STORAGE_AMOUNT,
        Some(_) => attached_near,
    };
```

If no router exists, `STORAGE_AMOUNT` (2 NEAR) is added to `required_near`. The precompile then makes an **external EVM sub-call** to the wNEAR ERC-20 contract's `transferFrom`, moving wNEAR from the user's EVM address to the engine's implicit EVM address:

```rust
// Lines 184-217
if required_near != ZERO_YOCTO {
    let engine_implicit_address = aurora_engine_sdk::types::near_account_to_evm_address(
        self.engine_account_id.as_bytes(),
    );
    let tx_data = transfer_from_args(
        sender.0.into(),
        engine_implicit_address.raw().0.into(),
        required_near.as_u128().into(),
    );
    // ...
    let (exit_reason, return_value) =
        handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
    // ...
}
```

The router version is **never updated synchronously**. It is only updated asynchronously via the `factory_update_address_version` NEAR callback, which runs after the router deployment promise resolves:

```rust
// engine/src/contract_methods/xcc.rs, lines 81-99
pub fn factory_update_address_version<...>(...) {
    // ...
    xcc::set_code_version_of_address(&mut io, &args.address, args.version);
}
```

**Attack sequence** (N XCC calls in one EVM transaction, first-time user):

1. Call 1: `get_code_version_of_address` → `None` → `required_near = attached_near + STORAGE_AMOUNT` → `transferFrom` moves 2 NEAR worth of wNEAR from user to engine implicit address → promise log emitted.
2. Call 2: `get_code_version_of_address` → still `None` (async callback hasn't run) → same charge → another `transferFrom` → another promise log.
3. …repeat for all N calls.
4. Promise chain 1 executes: router deployed, `withdraw_wnear_to_router` succeeds, NEAR sent to router.
5. Promise chain 2 executes: router deployment batch fails (`CreateAccount` on existing account), `factory_update_address_version` callback fails, `withdraw_wnear_to_router` detects failure and aborts:

```rust
// engine/src/contract_methods/xcc.rs, lines 33-35
if matches!(handler.promise_result_check(), Some(false)) {
    return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
}
```

The wNEAR already transferred to the engine's implicit EVM address in step 2 is **never unwrapped and never returned**. It remains permanently in the engine's implicit EVM address, which is not controlled by any private key and has no recovery mechanism in the engine.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

For N XCC precompile calls in a single EVM transaction by a first-time user, `(N-1) × STORAGE_AMOUNT` = `(N-1) × 2 NEAR` worth of wNEAR is permanently frozen in the engine's implicit EVM address (`near_account_to_evm_address(engine_account_id.as_bytes())`). There is no function in the engine that allows recovery of ERC-20 tokens from this address. The tokens are irrecoverable.

---

### Likelihood Explanation

**Medium.** Any EVM contract that makes multiple XCC precompile calls in a single transaction triggers this for a first-time user. This is a realistic pattern: a DeFi aggregator or multi-step protocol built on Aurora might issue several cross-contract calls in one transaction. The first time such a user interacts, their router does not exist, and every XCC call beyond the first silently drains and freezes their wNEAR. The user has no warning and no recourse.

---

### Recommendation

Apply the Checks-Effects-Interactions pattern:

1. **Synchronous state guard**: Before the external `handle.call()` to wNEAR's `transferFrom`, write a pending-deployment flag to storage for the sender's address. On subsequent calls within the same transaction (or before the async callback resolves), treat the address as already having a router and do not add `STORAGE_AMOUNT` again.
2. **Refund on failure**: In `withdraw_wnear_to_router`, if the previous promise failed, refund the wNEAR back to the user's EVM address rather than simply returning an error and leaving the tokens frozen.
3. **Idempotent deployment check**: In `handle_precompile_promise`, before creating a `CreateAccount` batch action, verify on-chain whether the sub-account already exists to avoid charging `STORAGE_AMOUNT` for an account that is in-flight.

---

### Proof of Concept

```
User deploys a malicious EVM contract `MultiXCC`:

contract MultiXCC {
    IXCCPrecompile constant XCC = IXCCPrecompile(0x516cded1d16af10cad47d6d49128e2eb7d27b372);
    IERC20 constant WNEAR = IERC20(<wnear_address>);

    function attack() external {
        // Approve engine implicit address to spend wNEAR (done beforehand)
        // Call XCC precompile 3 times in one transaction
        XCC.call(eager_call_args_1);  // charges STORAGE_AMOUNT, transferFrom succeeds
        XCC.call(eager_call_args_2);  // charges STORAGE_AMOUNT again (state not updated)
        XCC.call(eager_call_args_3);  // charges STORAGE_AMOUNT again
    }
}
```

**Result**: 3 × `STORAGE_AMOUNT` = 6 NEAR worth of wNEAR is transferred from the user. Only the first promise chain deploys the router successfully. The second and third chains fail at `CreateAccount`, `withdraw_wnear_to_router` aborts, and 4 NEAR worth of wNEAR is permanently frozen in the engine's implicit EVM address.

**Relevant code locations**:
- `engine-precompiles/src/xcc.rs` lines 177–217: state check then external call without synchronous state update
- `engine/src/xcc.rs` lines 212–282: `handle_precompile_promise` router deployment logic
- `engine/src/contract_methods/xcc.rs` lines 33–35: `withdraw_wnear_to_router` aborts on failed promise without refunding wNEAR [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** engine-precompiles/src/xcc.rs (L184-217)
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
        }
```

**File:** engine/src/xcc.rs (L212-282)
```rust
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

**File:** engine/src/contract_methods/xcc.rs (L33-35)
```rust
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
```

**File:** engine/src/contract_methods/xcc.rs (L81-99)
```rust
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
