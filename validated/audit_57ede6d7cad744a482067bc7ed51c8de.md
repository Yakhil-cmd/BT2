### Title
`factory_set_wnear_address` Mutation Causes Permanent Freeze of User wNEAR Tokens in In-Flight XCC Operations — (File: `engine/src/contract_methods/xcc.rs`)

---

### Summary

The global `wnear_address` state variable is read **at callback execution time** inside `withdraw_wnear_to_router`, not at the time the EVM-side `transferFrom` executes. If the engine owner calls `factory_set_wnear_address` between the EVM execution (which already transferred wNEAR from the user to the engine's implicit address on the **old** wNEAR ERC-20) and the NEAR promise callback, the callback will attempt to call `withdrawToNear` on the **new** wNEAR ERC-20 contract. Because the engine's implicit address holds no balance on the new contract, the callback fails and the user's wNEAR tokens are permanently frozen with no recovery path.

---

### Finding Description

The XCC flow is a two-step asynchronous process split across NEAR receipts:

**Step 1 — EVM execution (synchronous, within the user's transaction):**

The XCC precompile reads the current `wnear_address` from storage and executes an EVM-level `transferFrom` to move the user's wNEAR ERC-20 tokens to the engine's implicit address on the **old** wNEAR ERC-20 contract. [1](#0-0) 

It then schedules a `withdraw_wnear_to_router` NEAR promise. The `WithdrawWnearToRouterArgs` struct passed to this promise contains only `target` (the sender address) and `amount` — **it does not capture the wNEAR address used during EVM execution**. [2](#0-1) 

**Step 2 — NEAR promise callback (asynchronous, in a subsequent receipt):**

`withdraw_wnear_to_router` re-reads `wnear_address` from storage at callback time: [3](#0-2) 

It then calls `withdrawToNear` on whatever address `get_wnear_address` returns at that moment: [4](#0-3) 

**The vulnerability window:**

Between Step 1 and Step 2, the engine owner can call `factory_set_wnear_address`, which unconditionally overwrites the stored wNEAR address: [5](#0-4) [6](#0-5) 

When the callback then executes, it targets the **new** wNEAR ERC-20 contract, but the tokens were deposited into the engine's implicit address on the **old** wNEAR ERC-20 contract. The `withdrawToNear` call on the new contract fails (zero balance), the callback returns `ERR_WITHDRAW_FAILED`, and the user's wNEAR tokens remain permanently locked in the engine's implicit address on the old contract.

There is no `recoverERC20` or equivalent rescue function anywhere in the engine.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

The EVM-level `transferFrom` is committed to EVM state before the NEAR promise is dispatched. A failed NEAR callback does not roll back EVM state. The wNEAR tokens transferred to the engine's implicit address on the old wNEAR ERC-20 contract are irrecoverable. Every in-flight XCC operation that had already executed its EVM-side `transferFrom` at the moment `factory_set_wnear_address` is called loses its wNEAR permanently.

---

### Likelihood Explanation

The owner has a legitimate reason to call `factory_set_wnear_address` — for example, when the wNEAR NEP-141 contract is upgraded, migrated, or replaced due to a security incident. NEAR receipts are processed across blocks, so there is always a non-zero window between the EVM execution receipt and the `withdraw_wnear_to_router` callback receipt. On a busy network with many concurrent XCC users, multiple in-flight operations may be affected by a single `factory_set_wnear_address` call. The owner has no atomic mechanism to drain all in-flight XCC operations before changing the address.

---

### Recommendation

Embed the wNEAR address used during EVM execution directly into `WithdrawWnearToRouterArgs`, so the callback uses the same address that was used for the `transferFrom`, regardless of any subsequent `factory_set_wnear_address` call:

```rust
// engine-types/src/parameters/xcc.rs
pub struct WithdrawWnearToRouterArgs {
    pub target: Address,
    pub amount: Yocto,
+   pub wnear_address: Address,  // capture at EVM execution time
}
```

In `withdraw_wnear_to_router`, use `args.wnear_address` instead of re-reading from storage:

```rust
// engine/src/contract_methods/xcc.rs
- let wnear_address = aurora_engine_precompiles::xcc::state::get_wnear_address(&io);
+ let wnear_address = args.wnear_address;
```

---

### Proof of Concept

1. Owner deploys engine, sets `wnear_address = old_wnear_erc20`.
2. User calls the XCC precompile with NEAR attached. EVM execution runs `transferFrom(user, engine_implicit_address, amount)` on `old_wnear_erc20`. A `withdraw_wnear_to_router` NEAR receipt is scheduled.
3. Before the receipt executes (next block), owner calls `factory_set_wnear_address(new_wnear_erc20)`.
4. `withdraw_wnear_to_router` receipt executes. It reads `wnear_address = new_wnear_erc20` from storage.
5. It calls `withdrawToNear` on `new_wnear_erc20` for the engine's implicit address. The engine's implicit address has zero balance on `new_wnear_erc20`. The EVM call fails.
6. `withdraw_wnear_to_router` returns `ERR_WITHDRAW_FAILED`. The user's XCC call (chained as a callback) also fails.
7. The user's wNEAR tokens remain in the engine's implicit address on `old_wnear_erc20` with no recovery path. [7](#0-6) [8](#0-7)

### Citations

**File:** engine-precompiles/src/xcc.rs (L193-200)
```rust
            let wnear_address = state::get_wnear_address(&self.io);
            let context = aurora_evm::Context {
                address: wnear_address.raw(),
                caller: cross_contract_call::ADDRESS.raw(),
                apparent_value: U256::zero(),
            };
            let (exit_reason, return_value) =
                handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
```

**File:** engine-precompiles/src/xcc.rs (L262-268)
```rust
    pub fn get_wnear_address<I: IO>(io: &I) -> Address {
        let key = storage::bytes_to_key(KeyPrefix::CrossContractCall, WNEAR_KEY);
        io.read_storage(&key).map_or_else(
            || panic!("{ERR_MISSING_WNEAR_ADDRESS}"),
            |bytes| Address::try_from_slice(&bytes.to_vec()).expect(ERR_CORRUPTED_STORAGE),
        )
    }
```

**File:** engine/src/xcc.rs (L289-340)
```rust
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

**File:** engine/src/xcc.rs (L369-373)
```rust
/// Set the address of the `wNEAR` ERC-20 contract
pub fn set_wnear_address<I: IO>(io: &mut I, address: &Address) {
    let key = storage::bytes_to_key(KeyPrefix::CrossContractCall, WNEAR_KEY);
    io.write_storage(&key, address.as_bytes());
}
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

**File:** engine/src/contract_methods/xcc.rs (L102-115)
```rust
#[named]
pub fn factory_set_wnear_address<I: IO + Copy, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        let address = io.read_input_arr20()?;
        xcc::set_wnear_address(&mut io, &Address::from_array(address));
        Ok(())
    })
}
```
