### Title
Connector Account Update Breaks Withdrawal Accounting, Permanently Freezing Bridged ETH — (`engine/src/contract_methods/connector.rs`)

---

### Summary

`set_eth_connector_contract_account` atomically replaces the stored connector `AccountId` with no migration of the NEP-141 ETH balances held by the old connector. After the update, all `withdraw` calls are routed to the new connector (which holds zero NEP-141 ETH), making it impossible for existing depositors to exit Aurora. The NEP-141 ETH locked in the old connector becomes permanently stranded.

---

### Finding Description

The Aurora Engine stores a single pointer to the external eth-connector contract:

```rust
// engine/src/contract_methods/connector.rs:418-438
pub fn set_eth_connector_contract_account<I: IO + Copy, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        ...
        let args: SetEthConnectorContractAccountArgs = io.read_input_borsh()?;
        set_connector_account_id(io, &args.account);
        set_connector_withdraw_serialization_type(io, &args.withdraw_serialize_type);
        Ok(())
    })
}
```

This pointer is used in two critical places:

**1. Deposit routing** — `ft_on_transfer` checks whether the caller is the registered connector to decide whether to mint base ETH or ERC-20 tokens:

```rust
// engine/src/contract_methods/connector.rs:81-90
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)
} else {
    engine.receive_erc20_tokens(...)
};
```

**2. Withdrawal routing** — `withdraw` creates a promise targeting the registered connector:

```rust
// engine/src/contract_methods/connector.rs:58
return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
```

where `return_promise` resolves the target as:

```rust
// engine/src/contract_methods/connector.rs:606
target_account_id: get_connector_account_id(&io)?,
```

When the owner calls `set_eth_connector_contract_account` with a new connector address:

- The **old connector** still holds all NEP-141 ETH tokens deposited by users.
- The **new connector** starts with zero NEP-141 ETH balance.
- All subsequent `withdraw` calls route to the new connector, which has no NEP-141 ETH to disburse → every withdrawal fails.
- The old connector's NEP-141 ETH is permanently stranded because the engine no longer routes to it.
- The EVM-side ETH balances (stored in Aurora Engine's own trie via `set_balance`/`get_balance`) remain intact, so users can still transact within Aurora EVM — but they cannot bridge out.

There is no mechanism in `set_eth_connector_contract_account` to:
- Transfer NEP-141 ETH from the old connector to the new one.
- Record the old connector's outstanding balance so withdrawals can still be satisfied.

This is structurally identical to the KelpDAO M-01 pattern: a configuration pointer is updated, the old contract's balances are silently abandoned, and the accounting invariant (EVM ETH balance = NEP-141 ETH held by connector) is broken.

---

### Impact Explanation

**Permanent freezing of funds.** After a connector update:

- All NEP-141 ETH held by the old connector is permanently inaccessible through the engine's `withdraw` path.
- Users with EVM ETH balances cannot convert them back to NEP-141 ETH (cannot exit Aurora to NEAR or Ethereum).
- The magnitude equals the total ETH deposited before the connector update — potentially the entire bridged ETH supply.

---

### Likelihood Explanation

The `set_eth_connector_contract_account` function exists precisely to allow connector upgrades (e.g., bug fixes, feature additions). The CHANGES.md confirms it has already been used in production (v3.2.0 extended its argument structure). Any future connector upgrade — even a well-intentioned one — triggers this accounting break without any additional attacker action. The owner does not need to be malicious; the vulnerability fires on any legitimate connector migration.

---

### Recommendation

Before overwriting the connector account ID, the engine should either:

1. **Reject the update if the old connector holds a non-zero NEP-141 balance** (force the operator to drain the old connector first), or
2. **Record the old connector address alongside its outstanding balance** so that `withdraw` can route to the correct connector for each user's deposit epoch, or
3. **Require a two-step migration**: pause the contract, drain the old connector's NEP-141 ETH to the new connector, then update the pointer.

At minimum, the function should emit a clear warning and require an explicit acknowledgment that the caller has already migrated all NEP-141 ETH to the new connector.

---

### Proof of Concept

```
State before update:
  old_connector.ft_total_supply()  = 1000 ETH (NEP-141)
  aurora_engine.get_balance(alice) = 1000 ETH (EVM)

Owner calls:
  aurora_engine.set_eth_connector_contract_account(new_connector_id, Borsh)

State after update:
  new_connector.ft_total_supply()  = 0 ETH (NEP-141)
  old_connector.ft_total_supply()  = 1000 ETH (stranded, unreachable)
  aurora_engine.get_balance(alice) = 1000 ETH (EVM, still present)

Alice calls:
  aurora_engine.withdraw(eth_address, 1000 ETH)
  → promise: new_connector.engine_withdraw(alice, eth_address, 1000 ETH)
  → new_connector has 0 NEP-141 ETH → FAILS
  → Alice's EVM ETH is NOT burned (tx reverts)
  → Alice is permanently unable to exit Aurora
```

The 1000 NEP-141 ETH in `old_connector` is permanently frozen. Alice's EVM ETH is trapped inside Aurora with no exit path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** engine/src/contract_methods/connector.rs (L79-90)
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

**File:** engine/src/contract_methods/connector.rs (L550-567)
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

**File:** engine/src/engine.rs (L769-790)
```rust
    /// Mint base tokens for the recipient.
    ///
    /// IMPORTANT: This function should not panic, otherwise it won't
    /// be possible to return the tokens to the sender.
    pub fn receive_base_tokens(
        &mut self,
        args: &FtOnTransferArgs,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
        let amount = Wei::new_u128(args.amount.as_u128());
        let receipient = message_data.recipient;
        let balance = get_balance(&self.io, &receipient);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(errors::ERR_BALANCE_OVERFLOW)?;

        set_balance(&mut self.io, &receipient, &new_balance);

        sdk::log!("Mint {amount} base tokens for: {}", receipient.encode());

        Ok(None)
    }
```
