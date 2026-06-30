### Title
Race Condition in XCC Router Sub-Account Creation Permanently Freezes User wNEAR — (`engine-precompiles/src/xcc.rs`, `engine/src/xcc.rs`, `engine/src/contract_methods/xcc.rs`)

---

### Summary

The XCC precompile irrevocably transfers a user's wNEAR to the engine's implicit EVM address before the NEAR-side router sub-account creation promise executes. Because `fund_xcc_sub_account` is publicly callable by any NEAR account (when `wnear_account_id` is `None`), an attacker can race the engine's own router-creation batch for a victim's address. If the attacker's batch executes first, the engine's batch fails at `CreateAccount`, the downstream `withdraw_wnear_to_router` callback aborts, and the victim's `STORAGE_AMOUNT` (2 NEAR worth of wNEAR) is permanently stranded at the engine's implicit EVM address — an address with no private key and no recovery path.

---

### Finding Description

**Step 1 — wNEAR is seized before any promise executes.**

When a user calls the XCC precompile for the first time, `get_code_version_of_address` returns `None`, so `required_near = attached_near + STORAGE_AMOUNT`. [1](#0-0) 

The precompile immediately calls `transferFrom` on the wNEAR ERC-20, moving `required_near` from the user's EVM address to `engine_implicit_address` — a deterministic address derived from the engine's NEAR account ID. [2](#0-1) 

This EVM-level transfer is final. No refund path exists inside the precompile.

**Step 2 — Router creation is a separate, asynchronous NEAR promise.**

`handle_precompile_promise` builds a batch containing `CreateAccount`, `Transfer`, `DeployContract`, and `initialize`, targeting `{hex_address}.{aurora}`. [3](#0-2) 

This batch executes in the *next* NEAR block, not atomically with the EVM transaction.

**Step 3 — `fund_xcc_sub_account` is publicly callable.**

`fund_xcc_sub_account` has no access control when `wnear_account_id` is `None`. [4](#0-3) 

Any NEAR account can call it with an arbitrary `target` EVM address and ≥ 2 NEAR attached.

**Step 4 — If the attacker's batch executes first, the engine's batch fails.**

NEAR's `CreateAccount` action fails if the account already exists. The engine's batch then fails entirely. The `factory_update_address_version` callback detects the failure: [5](#0-4) 

`withdraw_wnear_to_router`, chained as the next callback, also aborts: [6](#0-5) 

The wNEAR that was transferred to `engine_implicit_address` in Step 1 is never withdrawn to the router. It remains at the engine's implicit EVM address permanently.

**Step 5 — The engine's implicit EVM address has no recovery path.**

`engine_implicit_address` is `near_account_to_evm_address(engine_account_id.as_bytes())`. [7](#0-6) 

This address has no corresponding private key. No admin function in the engine allows moving arbitrary EVM balances from this address. The wNEAR is permanently frozen.

---

### Impact Explanation

Each successful attack permanently freezes `STORAGE_AMOUNT = 2_000_000_000_000_000_000_000_000 yoctoNEAR` (2 NEAR) worth of wNEAR per victim. The funds are held at an EVM address that is unspendable by any party. This satisfies **Critical: Permanent freezing of funds**. [1](#0-0) 

---

### Likelihood Explanation

- `fund_xcc_sub_account` is a public NEAR method, callable by any account with ≥ 2 NEAR.
- NEAR transactions are visible in the mempool before block inclusion. An attacker monitors for EVM transactions that trigger first-time XCC usage (identifiable because `get_code_version_of_address` would return `None` for the sender).
- The attacker submits `fund_xcc_sub_account` targeting the victim's address in the same block. NEAR processes promises in the order their originating transactions appear in the block; if the attacker's transaction precedes the victim's EVM transaction in block ordering, the attacker's router-creation promise executes first.
- The cost to the attacker is 2 NEAR per victim (used for storage staking of the victim's router). The attack can be repeated for every new XCC user. [8](#0-7) 

---

### Recommendation

1. **Atomic wNEAR custody**: Do not transfer wNEAR from the user to the engine's implicit address until after the router sub-account is confirmed to exist (i.e., make the transfer a callback of a successful `CreateAccount` batch, not a precondition).
2. **Refund on failure**: In `withdraw_wnear_to_router`, when `promise_result_check()` returns `Some(false)`, emit a promise to return the stranded wNEAR from `engine_implicit_address` back to the original sender.
3. **Idempotent creation check**: Before issuing `CreateAccount`, query whether the sub-account already exists on-chain (via a view call or a try-create pattern) so that a pre-existing account is treated as `UpToDate` rather than a fatal failure.

---

### Proof of Concept

```
Attacker (NEAR account) monitors mempool.

Block N:
  T_victim: EVM submit → XCC precompile fires
    → transferFrom(victim_evm_addr, engine_implicit_addr, 2 NEAR wNEAR)  [FINAL]
    → emits promise log P_victim: CreateAccount({hex_victim}.aurora), Transfer, Deploy, Init

  T_attacker (submitted same block, ordered before T_victim's promise):
    → fund_xcc_sub_account(target=victim_evm_addr, wnear_account_id=None)
       attached_deposit = 2 NEAR
    → emits promise P_attacker: CreateAccount({hex_victim}.aurora), Transfer, Deploy, Init

Block N+1 (promise execution, attacker's promise first):
  P_attacker executes:
    CreateAccount({hex_victim}.aurora) → SUCCESS
    factory_update_address_version callback → SUCCESS (engine records version)

  P_victim executes:
    CreateAccount({hex_victim}.aurora) → FAIL (account exists)
    factory_update_address_version callback → FAIL (ERR_ROUTER_DEPLOY_FAILED)
    withdraw_wnear_to_router callback → FAIL (ERR_CALLBACK_OF_FAILED_PROMISE)

Result:
  - 2 NEAR wNEAR permanently frozen at engine_implicit_address (no private key, no recovery)
  - Victim's XCC call silently fails
  - Attacker spent 2 NEAR; victim lost 2 NEAR wNEAR
  - Attack repeatable for every new XCC user
``` [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** engine/src/xcc.rs (L115-130)
```rust
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

**File:** engine/src/xcc.rs (L226-237)
```rust
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

**File:** engine/src/contract_methods/xcc.rs (L124-148)
```rust
#[named]
pub fn fund_xcc_sub_account<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;

        let args: xcc::FundXccArgs = io.read_input_borsh()?;

        // If a specific wNEAR account is specified then this transaction must
        // come from a trusted user. The wNEAR account must be accurate for the
        // XCC sub-account to work properly.
        // This method can be public when `args.wnear_account_id.is_none()`
        // because then the Engine figures out the correct wNEAR account on
        // its own.
        if args.wnear_account_id.is_some() {
            require_owner_only(&state, &env.predecessor_account_id())?;
        }

        xcc::fund_xcc_sub_account(&io, handler, env, args)?;
        Ok(())
    })
```
