### Title
Stale ETH Connector Account ID After Migration Causes Permanent Fund Freeze — (File: engine/src/contract_methods/connector.rs)

### Summary
The Aurora Engine stores the ETH connector contract's NEAR account ID in its own storage. Every connector operation — including `withdraw`, `ft_transfer`, `ft_transfer_call`, `storage_deposit`, `storage_withdraw`, and `storage_unregister` — routes its NEAR promise to that stored account ID without any liveness check. If the ETH connector contract is migrated to a new NEAR account and the old contract is paused as part of that migration, the engine's stored reference becomes stale. All subsequent connector operations silently target the paused contract, causing them to fail and permanently freezing user funds bridged into Aurora.

### Finding Description
`return_promise` is the single shared dispatch path for every connector-facing operation in the engine: [1](#0-0) 

It unconditionally reads the connector account ID from storage: [2](#0-1) 

That stored account ID is the sole routing target for:

- `withdraw` → `return_promise(…, "engine_withdraw", …)` [3](#0-2) 
- `ft_transfer` → `return_promise(…, "engine_ft_transfer", …)` [4](#0-3) 
- `ft_transfer_call` → `return_promise(…, "engine_ft_transfer_call", …)` [5](#0-4) 
- `storage_deposit`, `storage_withdraw`, `storage_unregister` [6](#0-5) 

The update function `set_eth_connector_contract_account` exists: [7](#0-6) 

However, it provides no atomicity guarantee with respect to the connector migration itself, no validation that the new connector is live and functional, and no mechanism to drain or complete in-flight operations against the old connector before it is paused. There is therefore an unavoidable window — and a permanent freeze if the owner never calls the update — during which every connector operation targets a paused contract.

The `ft_on_transfer` path compounds the risk: it uses the same stored account ID to distinguish base-token deposits from ERC-20 deposits: [8](#0-7) 

If the old connector sends a pending `ft_on_transfer` after the stored ID has been updated to the new connector, the engine misclassifies it as an ERC-20 transfer, corrupting accounting.

### Impact Explanation
**Critical — Permanent freezing of funds.**

All ETH bridged into Aurora is held by the ETH connector contract on the NEAR side. If the connector is migrated and the engine's stored account ID is not updated atomically, users cannot withdraw their ETH (`withdraw` fails), cannot transfer it (`ft_transfer`/`ft_transfer_call` fail), and cannot recover storage deposits. Because the old connector is paused, the promises simply fail. If the owner never calls `set_eth_connector_contract_account`, the freeze is permanent. Even if the owner does call it, any in-flight operations against the old connector are lost.

### Likelihood Explanation
**Medium.** ETH connector upgrades are a planned, documented operational event in Aurora's lifecycle. The vulnerability window is the gap between pausing the old connector and updating the engine's stored account ID — a gap that exists in every migration unless the two actions are performed atomically in a single NEAR transaction batch, which the current code does not enforce or document.

### Recommendation
- **Short term:** Wrap the connector migration and the `set_eth_connector_contract_account` call in a single atomic NEAR batch transaction so the stored account ID is updated in the same block the old connector is paused. Add a liveness check inside `set_eth_connector_contract_account` (e.g., a view call to the new connector) before committing the update.
- **Long term:** Design and test a full migration strategy that drains in-flight connector operations before pausing the old contract, analogous to the recommendation in the source report.

### Proof of Concept
1. Alice bridges 10 ETH to Aurora. Her ETH is custodied by the ETH connector at NEAR account `connector.aurora`.
2. The Aurora team migrates the ETH connector to `connector-v2.aurora` and pauses `connector.aurora` as part of the migration.
3. Before the owner calls `set_eth_connector_contract_account`, Alice calls `withdraw` on the engine to retrieve her ETH.
4. `withdraw` calls `return_promise` → `get_connector_account_id` returns `connector.aurora` (the paused contract).
5. The NEAR promise targeting `connector.aurora` fails because the contract is paused.
6. Alice's 10 ETH remains locked in Aurora with no recovery path until — and only if — the owner updates the stored account ID and the new connector has the correct state to honour Alice's balance. [1](#0-0) [2](#0-1)

### Citations

**File:** engine/src/contract_methods/connector.rs (L43-59)
```rust
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;

    let args: WithdrawCallArgs = io.read_input_borsh()?;
    let args = borsh::to_vec(&EngineWithdrawCallArgs {
        sender_id: env.predecessor_account_id(),
        recipient_address: args.recipient_address,
        amount: args.amount,
    })
    .unwrap();

    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
}
```

**File:** engine/src/contract_methods/connector.rs (L81-90)
```rust
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };
```

**File:** engine/src/contract_methods/connector.rs (L248-265)
```rust
pub fn ft_transfer<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;
    let args = read_json_args(&io).and_then(|args: FtTransferArgs| {
        serde_json::to_vec(&(
            env.predecessor_account_id(),
            args.receiver_id,
            args.amount,
            args.memo,
        ))
        .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(io, env, "engine_ft_transfer", args, ONE_YOCTO)
}
```

**File:** engine/src/contract_methods/connector.rs (L267-286)
```rust
pub fn ft_transfer_call<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    // Check is payable
    env.assert_one_yocto()?;
    let args = read_json_args(&io).and_then(|args: FtTransferCallArgs| {
        serde_json::to_vec(&(
            env.predecessor_account_id(),
            args.receiver_id,
            args.amount,
            args.memo,
            args.msg,
        ))
        .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(io, env, "engine_ft_transfer_call", args, ONE_YOCTO)
}
```

**File:** engine/src/contract_methods/connector.rs (L288-339)
```rust
pub fn storage_deposit<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    let args = read_json_args(&io).and_then(|args: StorageDepositArgs| {
        serde_json::to_vec(&(
            env.predecessor_account_id(),
            args.account_id,
            args.registration_only,
        ))
        .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(
        io,
        env,
        "engine_storage_deposit",
        args,
        Yocto::new(env.attached_deposit()),
    )
}

pub fn storage_unregister<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;

    let args = read_json_args(&io).and_then(|args: StorageUnregisterArgs| {
        serde_json::to_vec(&(env.predecessor_account_id(), args.force))
            .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(io, env, "engine_storage_unregister", args, ONE_YOCTO)
}

pub fn storage_withdraw<I: IO + PromiseHandler + Copy, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;

    let args = read_json_args(&io).and_then(|args: StorageWithdrawArgs| {
        serde_json::to_vec(&(env.predecessor_account_id(), args.amount))
            .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(io, env, "engine_storage_withdraw", args, ONE_YOCTO)
}
```

**File:** engine/src/contract_methods/connector.rs (L417-438)
```rust
#[named]
pub fn set_eth_connector_contract_account<I: IO + Copy, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let is_private = env.assert_private_call();

        if is_private.is_err() {
            require_owner_only(&state, &env.predecessor_account_id())?;
        }

        let args: SetEthConnectorContractAccountArgs = io.read_input_borsh()?;

        set_connector_account_id(io, &args.account);
        set_connector_withdraw_serialization_type(io, &args.withdraw_serialize_type);

        Ok(())
    })
}
```

**File:** engine/src/contract_methods/connector.rs (L550-560)
```rust
fn get_connector_account_id<I: IO>(io: &I) -> Result<AccountId, ContractError> {
    io.read_storage(&construct_contract_key(
        EthConnectorStorageId::EthConnectorAccount,
    ))
    .ok_or(errors::ERR_CONNECTOR_STORAGE_KEY_NOT_FOUND)
    .and_then(|x| {
        x.to_value()
            .map_err(|_| errors::ERR_BORSH_DESERIALIZE.as_bytes())
    })
    .map_err(Into::into)
}
```

**File:** engine/src/contract_methods/connector.rs (L598-616)
```rust
fn return_promise<I: IO + PromiseHandler, E: Env>(
    mut io: I,
    env: &E,
    method: &str,
    args: Vec<u8>,
    deposit: Yocto,
) -> Result<(), ContractError> {
    let promise_args = PromiseCreateArgs {
        target_account_id: get_connector_account_id(&io)?,
        method: method.to_string(),
        args,
        attached_balance: deposit,
        attached_gas: calculate_attached_gas(env),
    };
    let promise_id = io.promise_create_call(&promise_args);

    io.promise_return(promise_id);

    Ok(())
```
