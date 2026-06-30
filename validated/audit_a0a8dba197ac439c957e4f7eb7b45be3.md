### Title
`set_eth_connector_contract_account` Connector Pointer Swap Permanently Freezes All User ETH Balances in the Old Connector - (File: `engine/src/contract_methods/connector.rs`)

### Summary

The Aurora Engine stores a single mutable pointer to the external ETH-connector contract (`EthConnectorStorageId::EthConnectorAccount`). The owner can atomically replace this pointer via `set_eth_connector_contract_account`. After the swap, every engine function that forwards calls to the connector (`withdraw`, `ft_transfer`, `ft_transfer_call`, `storage_deposit`, `storage_unregister`, `storage_withdraw`, `ft_balance_of`, `ft_total_supply`) targets the **new** connector exclusively. The old connector still holds all previously deposited user ETH balances (NEP-141 tokens), but the engine no longer calls it, and the old connector's `engine_withdraw` method enforces `"Method can be called only by aurora engine"`. There is no migration path, no drain window, and no way for users to recover their funds from the old connector. All balances are permanently frozen.

### Finding Description

The engine stores the connector account ID in NEAR storage under `EthConnectorStorageId::EthConnectorAccount`. The admin-callable function `set_eth_connector_contract_account` overwrites this key atomically:

```rust
// engine/src/contract_methods/connector.rs  lines 418-438
pub fn set_eth_connector_contract_account<I: IO + Copy, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        ...
        set_connector_account_id(io, &args.account);          // <-- pointer overwritten
        set_connector_withdraw_serialization_type(io, &args.withdraw_serialize_type);
        Ok(())
    })
}
``` [1](#0-0) 

Every connector-forwarding helper (`return_promise`) reads this pointer at call time:

```rust
// engine/src/contract_methods/connector.rs  lines 598-616
fn return_promise<I: IO + PromiseHandler, E: Env>(...) -> Result<(), ContractError> {
    let promise_args = PromiseCreateArgs {
        target_account_id: get_connector_account_id(&io)?,   // <-- always the current pointer
        ...
    };
    ...
}
``` [2](#0-1) 

The `withdraw` entrypoint uses `return_promise` to forward to `engine_withdraw` on the connector:

```rust
// engine/src/contract_methods/connector.rs  lines 43-59
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(...) -> Result<(), ContractError> {
    ...
    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
}
``` [3](#0-2) 

The same `return_promise` path is used by `ft_transfer`, `ft_transfer_call`, `storage_deposit`, `storage_unregister`, `storage_withdraw`, `storage_balance_of`, and `ft_total_eth_supply_on_near`. [4](#0-3) 

The old connector enforces that only the aurora engine account may call `engine_withdraw` — confirmed by the test assertion `"Method can be called only by aurora engine"`: [5](#0-4) 

Additionally, `ft_on_transfer` uses the stored pointer to distinguish base-ETH deposits from ERC-20 deposits:

```rust
// engine/src/contract_methods/connector.rs  line 81
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)   // only if caller == current connector
} else {
    engine.receive_erc20_tokens(...)
};
``` [6](#0-5) 

After the pointer swap, any `ft_on_transfer` call from the old connector is misclassified as an ERC-20 transfer and will fail, breaking the deposit path for the old connector as well.

The `ExitToEth` precompile (`engine-precompiles/src/native.rs`) also reads the connector account at execution time and would target the new connector, which holds no balances: [7](#0-6) 

### Impact Explanation

**Critical — Permanent freezing of funds.**

All user ETH balances (NEP-141 tokens) held in the old connector contract become permanently inaccessible:

- The engine's `withdraw` function calls `engine_withdraw` on the **new** connector, which has zero balances, so withdrawals silently succeed with no actual token movement or fail.
- The old connector's `engine_withdraw` is gated to the aurora engine account only; no user or third party can call it directly.
- There is no migration, no drain window, and no escape hatch for users to recover funds from the old connector.
- The total ETH supply bridged into Aurora at the time of the swap is permanently frozen.

### Likelihood Explanation

The `set_eth_connector_contract_account` function is an explicitly documented, intentional admin operation used when the connector contract needs to be replaced (e.g., a new deployment rather than an upgrade). The workspace test infrastructure calls it during normal setup: [8](#0-7) 

Any legitimate connector replacement — a routine operational action — triggers this freeze. No malice is required; the admin simply performs the intended upgrade procedure.

### Recommendation

Before overwriting the connector pointer, the engine should either:

1. **Drain the old connector first**: Require that the old connector's total supply is zero before allowing the pointer swap, or
2. **Provide a migration window**: Keep the old connector account ID accessible so users can call a dedicated `withdraw_from_old_connector` function that still targets the old account, or
3. **Atomic migration**: As part of `set_eth_connector_contract_account`, schedule a promise that transfers all balances from the old connector to the new one before the pointer is updated.

### Proof of Concept

1. User deposits 10 ETH into Aurora. The old connector (`old-connector.near`) now holds 10 ETH worth of NEP-141 tokens credited to the user.
2. Admin calls `set_eth_connector_contract_account` with `new-connector.near` (a freshly deployed connector with zero balances).
3. The engine's stored pointer is now `new-connector.near`.
4. User calls `engine.withdraw(recipient_eth_address, 10_ETH)`.
5. The engine's `withdraw` function calls `return_promise` → `get_connector_account_id` returns `new-connector.near` → `engine_withdraw` is called on `new-connector.near`.
6. `new-connector.near` has no balance for the user; the call fails or burns nothing.
7. User's 10 ETH remains locked in `old-connector.near` forever. The user cannot call `old-connector.near::engine_withdraw` directly because it enforces `"Method can be called only by aurora engine"`, and the engine no longer routes to it.

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

**File:** engine/src/contract_methods/connector.rs (L80-90)
```rust
        let args: FtOnTransferArgs = read_json_args(&io)?;
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

**File:** engine/src/contract_methods/connector.rs (L248-355)
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

pub fn storage_balance_of<I: IO + Copy + PromiseHandler + Env>(io: I) -> Result<(), ContractError> {
    let args = io.read_input().to_vec();
    return_promise(io, &io, "storage_balance_of", args, ZERO_YOCTO)
}

pub fn ft_total_eth_supply_on_near<I: IO + Copy + PromiseHandler + Env>(
    io: I,
) -> Result<(), ContractError> {
    return_promise(io, &io, "ft_total_supply", Vec::new(), ZERO_YOCTO)
}

pub fn ft_balance_of<I: IO + Copy + PromiseHandler + Env>(io: I) -> Result<(), ContractError> {
    let args = io.read_input().to_vec();
    return_promise(io, &io, "ft_balance_of", args, ZERO_YOCTO)
}
```

**File:** engine/src/contract_methods/connector.rs (L418-438)
```rust
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

**File:** engine-tests-connector/src/connector.rs (L425-432)
```rust
    let res = user_acc
        .call(contract.eth_connector_contract.id(), "engine_withdraw")
        .args_borsh((user_acc.id(), *RECIPIENT_ADDRESS, withdraw_amount))
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_failure());
    assert!(contract.check_error_message(&res, "Method can be called only by aurora engine")?);
```

**File:** engine-precompiles/src/native.rs (L897-904)
```rust
                let serialize_fn = match get_withdraw_serialize_type(&self.io)? {
                    WithdrawSerializeType::Json => json_args,
                    WithdrawSerializeType::Borsh => borsh_args,
                };
                let eth_connector_account_id = self.get_eth_connector_contract_account()?;

                (
                    eth_connector_account_id,
```

**File:** engine-tests/src/utils/workspace.rs (L91-95)
```rust
    let result = aurora
        .set_eth_connector_contract_account(contract_account.id(), WithdrawSerializeType::Borsh)
        .transact()
        .await?;
    assert!(result.is_success());
```
