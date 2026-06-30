### Title
Changing ETH Connector Account via `set_eth_connector_contract_account` Permanently Freezes All User Balances in Old Connector - (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

`set_eth_connector_contract_account` atomically redirects all engine connector operations to a new external contract account without any mechanism to migrate existing user NEP-141 ETH balances from the old connector. All user funds held in the old connector become permanently inaccessible through the engine's intended interface.

---

### Finding Description

The Aurora Engine stores a pointer to an external ETH connector contract in its key-value storage under `EthConnectorStorageId::EthConnectorAccount`. Every user-facing connector operation — `withdraw`, `ft_transfer`, `ft_transfer_call`, `storage_deposit`, `storage_withdraw`, `ft_metadata`, `ft_balance_of`, `ft_total_supply`, etc. — is dispatched through the internal `return_promise` helper, which resolves the target account by calling `get_connector_account_id` at call time. [1](#0-0) 

`get_connector_account_id` simply reads the stored account ID from storage: [2](#0-1) 

The owner (or a private self-call) can replace this pointer at any time by calling `set_eth_connector_contract_account`: [3](#0-2) 

The function writes the new account ID and serialization type, then returns. There is no:
- balance snapshot or transfer from old connector to new connector,
- check that the new connector holds equivalent balances,
- migration callback, or
- any mechanism for users to recover funds from the old connector through the engine.

After the call, every subsequent engine operation targets the new connector. The old connector retains all previously deposited NEP-141 ETH balances, but the engine never routes to it again.

The `withdraw` function, for example, constructs its promise entirely through `return_promise`: [4](#0-3) 

The same pattern applies to `ft_transfer`, `ft_transfer_call`, `storage_deposit`, `storage_withdraw`, `ft_balance_of`, `ft_total_eth_supply_on_near`, and `ft_metadata` — all delegate through `return_promise` → `get_connector_account_id`. [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

All user ETH balances (NEP-141 tokens) held in the old connector contract become permanently inaccessible through the engine after the connector account is changed. Users cannot `withdraw` their ETH back to Ethereum, cannot `ft_transfer` it, and cannot receive correct balance readings. The old connector contract continues to hold the actual token supply, but the engine's entire connector interface is now pointed elsewhere. There is no recovery path within the engine's production interface.

---

### Likelihood Explanation

The `set_eth_connector_contract_account` function is an intended production upgrade path — it is exposed as a named entry point in `lib.rs`, has a workspace wrapper in `engine-workspace/src/contract.rs`, and is exercised in integration test setup (`engine-tests/src/utils/workspace.rs` and `engine-tests-connector/src/utils.rs`). [6](#0-5) 

Any legitimate connector upgrade (e.g., deploying a new version of the ETH connector contract) would naturally involve calling this function. Because there is no migration mechanism, any such upgrade silently freezes all existing user balances. The likelihood is therefore tied directly to the frequency of connector upgrades, which is a planned operational activity.

---

### Recommendation

1. **Add a balance migration step**: Before updating the stored connector account ID, read the total supply from the old connector and verify (or transfer) it to the new connector, or require the caller to supply proof of equivalent balances.
2. **Require zero outstanding balances**: Reject the account change unless the old connector reports a zero total supply, forcing operators to drain all user balances before switching.
3. **Emit a migration event / provide a recovery method**: At minimum, expose a method that allows users to claim their balances from the old connector directly, bypassing the engine's routing.

---

### Proof of Concept

1. User Alice deposits ETH into Aurora. The ETH connector contract `old_connector.near` now holds 100 ETH worth of NEP-141 tokens credited to Alice.
2. The engine owner calls `set_eth_connector_contract_account` with `account = "new_connector.near"`.
3. `set_connector_account_id` overwrites the stored pointer. `new_connector.near` has zero balances.
4. Alice calls `withdraw` on the engine. `return_promise` resolves `get_connector_account_id()` → `"new_connector.near"` and dispatches `engine_withdraw` to the new connector.
5. The new connector has no record of Alice's balance and the call fails (or succeeds with zero effect).
6. `old_connector.near` still holds Alice's 100 ETH worth of tokens, but the engine never routes to it again. Alice's funds are permanently frozen. [7](#0-6) [8](#0-7)

### Citations

**File:** engine/src/contract_methods/connector.rs (L43-58)
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
```

**File:** engine/src/contract_methods/connector.rs (L326-354)
```rust
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

**File:** engine/src/contract_methods/connector.rs (L562-567)
```rust
pub fn set_connector_account_id<I: IO + Copy>(mut io: I, account_id: &AccountId) {
    io.write_borsh(
        &construct_contract_key(EthConnectorStorageId::EthConnectorAccount),
        account_id,
    );
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

**File:** engine-tests/src/utils/workspace.rs (L91-95)
```rust
    let result = aurora
        .set_eth_connector_contract_account(contract_account.id(), WithdrawSerializeType::Borsh)
        .transact()
        .await?;
    assert!(result.is_success());
```
