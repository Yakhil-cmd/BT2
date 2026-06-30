### Title
Owner Can Immediately Swap ETH Connector to Malicious Account, Redirecting All User Fund Flows — (`engine/src/contract_methods/connector.rs`)

---

### Summary

`set_eth_connector_contract_account` allows the engine owner (or any self-call) to atomically replace the stored ETH connector account ID with any arbitrary NEAR account, with no validation of the new account and no timelock. Because every fund-moving cross-contract call in the engine resolves its target at call time from this single storage slot, a malicious or compromised owner can instantly redirect all user withdrawals, FT transfers, and storage operations to an attacker-controlled contract, and simultaneously enable that contract to mint arbitrary ETH balances inside the EVM.

---

### Finding Description

`set_eth_connector_contract_account` in `engine/src/contract_methods/connector.rs` is the sole write path for the `EthConnectorStorageId::EthConnectorAccount` storage slot:

```rust
// engine/src/contract_methods/connector.rs  L418-438
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

        set_connector_account_id(io, &args.account);          // ← overwrites slot
        set_connector_withdraw_serialization_type(io, &args.withdraw_serialize_type);

        Ok(())
    })
}
```

There is no check that `args.account` is a legitimate ETH connector contract, no registry lookup, and no timelock. The change takes effect in the same transaction.

Every fund-moving method in the engine resolves its cross-contract call target through the private `return_promise` helper, which reads this slot at call time:

```rust
// engine/src/contract_methods/connector.rs  L598-616
fn return_promise<I: IO + PromiseHandler, E: Env>(
    mut io: I,
    env: &E,
    method: &str,
    args: Vec<u8>,
    deposit: Yocto,
) -> Result<(), ContractError> {
    let promise_args = PromiseCreateArgs {
        target_account_id: get_connector_account_id(&io)?,   // ← reads slot
        method: method.to_string(),
        args,
        attached_balance: deposit,
        attached_gas: calculate_attached_gas(env),
    };
    let promise_id = io.promise_create_call(&promise_args);
    io.promise_return(promise_id);
    Ok(())
}
```

All of the following public entry points call `return_promise` and are therefore affected:

| Entry point | Method forwarded to connector |
|---|---|
| `withdraw` | `engine_withdraw` |
| `ft_transfer` | `engine_ft_transfer` |
| `ft_transfer_call` | `engine_ft_transfer_call` |
| `storage_deposit` | `engine_storage_deposit` |
| `storage_unregister` | `engine_storage_unregister` |
| `storage_withdraw` | `engine_storage_withdraw` |
| `ft_metadata` | `ft_metadata` |
| `ft_total_eth_supply_on_near` | `ft_total_supply` |
| `ft_balance_of` | `ft_balance_of` |
| `storage_balance_of` | `storage_balance_of` |

A second, independent impact exists in `ft_on_transfer`. The engine uses the stored connector account ID to decide whether incoming tokens are native ETH (base tokens) or ERC-20 tokens:

```rust
// engine/src/contract_methods/connector.rs  L81-90
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)   // ← mints ETH inside EVM
} else {
    engine.receive_erc20_tokens(...)
};
```

Once the slot is overwritten to the attacker's account, the attacker's contract can call `ft_on_transfer` on the engine and, because `predecessor_account_id == get_connector_account_id(&io)?` is now true, the engine will call `receive_base_tokens` and credit arbitrary ETH balances to any EVM address the attacker specifies.

---

### Impact Explanation

**Critical — Direct theft of user funds in motion and insolvency.**

- Every user who calls `withdraw` after the swap has their NEP-141 ETH tokens forwarded to the attacker's contract instead of the legitimate connector. The attacker's contract can absorb those tokens without releasing the corresponding ETH on Ethereum.
- Every user who calls `ft_transfer` or `ft_transfer_call` has their token transfer routed to the attacker's contract.
- The attacker's contract can call `ft_on_transfer` on the engine to mint unbacked ETH balances inside the EVM, creating insolvency: the EVM ledger shows more ETH than the connector actually holds.

---

### Likelihood Explanation

Requires the engine owner account to be malicious or compromised. The owner is a single NEAR account set at initialization. There is no timelock, no multi-sig enforcement at the contract level, and no registry of approved connectors. The call is a single atomic transaction with no delay. The hashchain records the event but does not prevent it. This is the same trust-model flaw identified in the PoolTogether report: the design gives a single privileged key unchecked, immediate power over all user funds.

---

### Recommendation

1. **Timelock**: Require a mandatory delay (e.g., 48 hours) between proposing and applying a connector swap, enforced on-chain.
2. **Registry validation**: Maintain an on-chain allowlist of approved connector account IDs; reject any `set_eth_connector_contract_account` call whose argument is not in the allowlist.
3. **Two-step ownership**: Require a separate confirmation transaction from the new connector account before the swap takes effect, proving the target account is a live, cooperative contract.
4. **Governance**: Transfer the owner role to a time-locked governance contract so no single key can execute the swap unilaterally.

---

### Proof of Concept

1. Owner calls `set_eth_connector_contract_account` with `account = attacker.near` (a NEAR contract that implements `engine_withdraw`, `engine_ft_transfer`, etc. as no-ops that keep all received tokens).
2. `set_connector_account_id` writes `attacker.near` to `EthConnectorStorageId::EthConnectorAccount`.
3. User calls `withdraw(recipient_eth_address, 1_000_000)` on the engine, attaching 1 yoctoNEAR.
4. `return_promise` reads the slot, gets `attacker.near`, and creates a cross-contract call to `attacker.near::engine_withdraw(...)` with the user's NEP-141 ETH tokens attached.
5. `attacker.near` receives the tokens and does not release ETH on Ethereum. Funds are stolen.
6. Separately, `attacker.near` calls `ft_on_transfer` on the engine with `{"sender_id": "victim.near", "amount": "1000000000000000000", "msg": "<evm_address>"}`.
7. Because `predecessor_account_id == get_connector_account_id(&io)?` is now true, the engine calls `receive_base_tokens` and mints 1 ETH inside the EVM to the attacker's EVM address, with no real ETH backing it.

**Relevant file and lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** engine/src/lib.rs (L700-707)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn set_eth_connector_contract_account() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::set_eth_connector_contract_account(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
