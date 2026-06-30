Now I have enough context to write the finding. Let me verify the `return_promise` function and the `ExitToEthereum` path one more time.### Title
`set_eth_connector_contract_account` Allows Overwriting the Live Connector Address, Permanently Freezing All Bridged ETH - (`engine/src/contract_methods/connector.rs`)

---

### Summary

`set_eth_connector_contract_account` can be called by the engine owner at any time to replace the stored ETH connector account ID with a new one. Because every ETH withdrawal path in the engine reads this stored account ID at call time and directs its cross-contract promise to it, changing the account while users hold bridged ETH balances severs the link between the engine's internal EVM balances and the NEP-141 token pool held by the old connector. All bridged ETH becomes permanently unwithdrawable.

---

### Finding Description

The engine stores the ETH connector account ID in a single storage slot keyed by `EthConnectorStorageId::EthConnectorAccount`. The owner (or a private/self call) can overwrite this slot unconditionally via `set_eth_connector_contract_account`:

```rust
// engine/src/contract_methods/connector.rs  lines 418-438
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
        set_connector_account_id(io, &args.account);          // unconditional overwrite
        set_connector_withdraw_serialization_type(io, &args.withdraw_serialize_type);
        Ok(())
    })
}
```

There is no guard that checks whether the old connector still holds user funds, nor any migration step.

Every ETH withdrawal path reads this slot at execution time and targets the result as the cross-contract call destination:

**`return_promise` (used by `withdraw`, `ft_transfer`, `ft_transfer_call`, `storage_deposit`, `storage_unregister`, `storage_withdraw`, `ft_metadata`):**
```rust
// engine/src/contract_methods/connector.rs  lines 605-606
let promise_args = PromiseCreateArgs {
    target_account_id: get_connector_account_id(&io)?,   // reads current slot
    ...
};
```

**`ExitToNear` precompile (ETH base-token exit):**
```rust
// engine-precompiles/src/native.rs  line 431
let eth_connector_account_id = self.get_eth_connector_contract_account()?;
exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
```

**`ExitToEthereum` precompile (ETH base-token exit):**
```rust
// engine-precompiles/src/native.rs  lines 901-904
let eth_connector_account_id = self.get_eth_connector_contract_account()?;
(eth_connector_account_id, ...)
```

**`ft_on_transfer` (incoming deposit routing):**
```rust
// engine/src/contract_methods/connector.rs  line 81
if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)   // only reached if caller == stored connector
```

After the connector account is changed:
- All `withdraw` / `ft_transfer` / `ft_transfer_call` calls are routed to the **new** connector, which holds zero ETH balance. The calls either fail or succeed vacuously, returning nothing to the user.
- `ExitToNear` and `ExitToEthereum` precompile-triggered promises target the new connector; the `ft_transfer` / `withdraw` calls on it fail because it has no funds.
- `ft_on_transfer` from the **old** connector is no longer recognized as a base-token deposit; it falls into the ERC-20 branch and will fail or credit the wrong token.
- The old connector still holds all the NEP-141 ETH tokens, but the engine has no path to reach them.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

All ETH that users have bridged into Aurora is backed by NEP-141 tokens held by the old connector contract. After the connector account is overwritten, no user can withdraw their ETH via any supported path (`withdraw`, `exitToNear`, `exitToEthereum`). The EVM balances remain in the engine's state trie but are unreachable. There is no recovery path without a further owner action to restore the original connector address, and even that restoration is not guaranteed to be possible if the owner account is rotated or the engine is upgraded in the interim.

---

### Likelihood Explanation

The owner is a legitimate protocol participant who may call `set_eth_connector_contract_account` to upgrade or replace the connector contract — a plausible operational action. The function is already called once during deployment setup (as shown in `engine-tests/src/utils/workspace.rs` and `engine-tests-connector/src/utils.rs`). A second call during a connector upgrade, with no safeguard preventing it while funds are live, is a realistic scenario. No attacker compromise is required; the owner acting in good faith is sufficient to trigger the freeze.

---

### Recommendation

Add a guard that prevents overwriting the connector account when the old connector still holds a non-zero total supply of bridged ETH. Concretely:

1. Before writing the new account ID, make a cross-contract view call to the **old** connector's `ft_total_supply` and reject the change if it is non-zero.
2. Alternatively, remove the ability to change the connector account after initial deployment (set-once semantics), analogous to the fix recommended in the original report.
3. If migration is genuinely needed, require a two-phase process: first drain all user balances from the old connector to the new one atomically, then update the pointer.

---

### Proof of Concept

1. Users bridge ETH into Aurora. The old connector (`old_connector.near`) holds `N` NEP-141 ETH tokens. Users have corresponding EVM balances in the engine.

2. Owner calls `set_eth_connector_contract_account` with `account = new_connector.near`. The storage slot `EthConnectorStorageId::EthConnectorAccount` is overwritten. [1](#0-0) 

3. A user calls `withdraw` to retrieve their ETH. `return_promise` reads the connector slot and creates a promise targeting `new_connector.near` with method `engine_withdraw`. [2](#0-1) 
   `new_connector.near` has zero balance; the call fails or returns nothing. The user's EVM balance was already debited by the engine.

4. A user calls the `exitToNear` precompile. `ExitToNear::run` fetches the connector account and constructs an `ft_transfer` promise to `new_connector.near`. [3](#0-2) 
   Same result: the promise targets an empty contract.

5. A user calls the `exitToEthereum` precompile. `ExitToEthereum::run` fetches the connector account and constructs a `withdraw` promise to `new_connector.near`. [4](#0-3) 
   Same result.

6. All `N` NEP-141 ETH tokens remain locked in `old_connector.near` with no engine-accessible path to retrieve them. All user EVM ETH balances are permanently frozen. [5](#0-4)

### Citations

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

**File:** engine/src/contract_methods/connector.rs (L605-612)
```rust
    let promise_args = PromiseCreateArgs {
        target_account_id: get_connector_account_id(&io)?,
        method: method.to_string(),
        args,
        attached_balance: deposit,
        attached_gas: calculate_attached_gas(env),
    };
    let promise_id = io.promise_create_call(&promise_args);
```

**File:** engine-precompiles/src/native.rs (L431-432)
```rust
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
```

**File:** engine-precompiles/src/native.rs (L901-904)
```rust
                let eth_connector_account_id = self.get_eth_connector_contract_account()?;

                (
                    eth_connector_account_id,
```
