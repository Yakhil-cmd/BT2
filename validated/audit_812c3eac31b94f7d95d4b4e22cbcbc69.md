### Title
Eth-Connector Account Replacement Without Outstanding-Balance Validation Permanently Freezes Bridged ETH — (`File: engine/src/contract_methods/connector.rs`)

---

### Summary

`set_eth_connector_contract_account` atomically overwrites the stored connector account ID with a new one, with no check for outstanding ETH balances held by the old connector. Any ETH that was deposited through the old connector and is still custodied there becomes permanently unreachable: the engine will route all future `withdraw` and `ft_transfer` calls to the new connector, while the old connector still holds the real ETH. This is the direct analog of the reported "remove asset without borrow validation" pattern.

---

### Finding Description

The `set_eth_connector_contract_account` function in `engine/src/contract_methods/connector.rs` simply writes the new account ID and serialization type to storage:

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
``` [1](#0-0) 

The stored connector account ID is the single source of truth used by every outbound path. The `ExitToNear` precompile reads it at call time to decide where to send the `ft_transfer`/`ft_transfer_call` promise:

```rust
ExitToNearParams::BaseToken(ref exit_params) => {
    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
}
``` [2](#0-1) 

The `ExitToEthereum` precompile does the same:

```rust
let eth_connector_account_id = self.get_eth_connector_contract_account()?;
``` [3](#0-2) 

`ft_on_transfer` uses the stored connector account to decide whether an incoming transfer is base-ETH or an ERC-20:

```rust
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)
} else {
    engine.receive_erc20_tokens(...)
};
``` [4](#0-3) 

The `withdraw` function forwards the call to the connector via a promise:

```rust
return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
``` [5](#0-4) 

None of these paths have any fallback to the old connector. Once `set_eth_connector_contract_account` is called with a new account, the old connector's custodied ETH is permanently orphaned.

The `set_connector_account_id` helper performs a raw storage overwrite with no balance check:

```rust
pub fn set_connector_account_id<I: IO + Copy>(mut io: I, account_id: &AccountId) {
    io.write_borsh(
        &construct_contract_key(EthConnectorStorageId::EthConnectorAccount),
        account_id,
    );
}
``` [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

All ETH that users have bridged to Aurora and that is custodied in the old connector contract becomes permanently inaccessible. Users cannot withdraw (the engine sends the `engine_withdraw` promise to the new connector, which has no record of their balance). The EVM balances on Aurora remain intact, but the backing ETH on NEAR is stranded in the old connector with no engine-level path to recover it.

---

### Likelihood Explanation

**Medium.** The function is owner-only (or private-call), so it requires the contract owner to invoke it. However:

- The owner is a single account, not a multisig, and the function has no timelock.
- The function is a legitimate operational action (connector migration), so it will be called in practice.
- There is no warning, no balance check, and no migration helper in the codebase, making an accidental or premature switch highly plausible during any connector upgrade.

---

### Recommendation

Before overwriting the connector account ID, verify that the old connector holds zero outstanding ETH balance (i.e., the total supply of ETH on Aurora is zero, or a migration has been completed). At minimum, add a two-step migration: record the old connector alongside the new one, allow users to drain the old connector, and only then remove the old reference. Alternatively, require an explicit zero-balance attestation from the old connector as a promise result before committing the switch.

---

### Proof of Concept

1. Alice bridges 10 ETH to Aurora. The old connector (`old-connector.near`) custodies 10 ETH; Alice has 10 ETH balance in the Aurora EVM.
2. The owner calls `set_eth_connector_contract_account` with `account = "new-connector.near"`.
   - `set_connector_account_id` overwrites the storage key immediately.
   - No check is made against the old connector's balance.
3. Alice calls `withdraw` on Aurora to recover her ETH.
   - `withdraw` builds an `engine_withdraw` promise targeting `new-connector.near`.
   - `new-connector.near` has no record of Alice's deposit and no ETH to send.
   - The withdrawal fails or sends nothing.
4. Alice's 10 ETH remains locked in `old-connector.near` forever, with no engine-level path to retrieve it. [7](#0-6) [8](#0-7)

### Citations

**File:** engine/src/contract_methods/connector.rs (L58-58)
```rust
    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
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

**File:** engine/src/contract_methods/connector.rs (L562-567)
```rust
pub fn set_connector_account_id<I: IO + Copy>(mut io: I, account_id: &AccountId) {
    io.write_borsh(
        &construct_contract_key(EthConnectorStorageId::EthConnectorAccount),
        account_id,
    );
}
```

**File:** engine-precompiles/src/native.rs (L430-433)
```rust
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
```

**File:** engine-precompiles/src/native.rs (L901-901)
```rust
                let eth_connector_account_id = self.get_eth_connector_contract_account()?;
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
