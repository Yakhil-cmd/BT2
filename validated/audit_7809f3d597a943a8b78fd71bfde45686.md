### Title
Owner Can Instantly Redirect All ETH Withdrawals to a Malicious Connector Account - (File: engine/src/contract_methods/connector.rs)

### Summary
The `set_eth_connector_contract_account` function allows the Aurora Engine owner to instantly replace the ETH connector contract account with any arbitrary NEAR account, with no timelock or delay. The `withdraw` function unconditionally routes all user ETH withdrawal cross-contract calls to this stored account. A malicious owner can frontrun a user's `withdraw` transaction by swapping the connector to a malicious contract, causing the user's NEP-141 ETH tokens to be stolen.

### Finding Description
`set_eth_connector_contract_account` in `engine/src/contract_methods/connector.rs` stores a new connector account ID immediately upon owner invocation:

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
        set_connector_account_id(io, &args.account);          // ← instant write, no delay
        set_connector_withdraw_serialization_type(io, &args.withdraw_serialize_type);
        Ok(())
    })
}
``` [1](#0-0) 

The `withdraw` function then blindly routes every user withdrawal to whatever account is currently stored:

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
    }).unwrap();
    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)  // ← calls stored connector
}
``` [2](#0-1) 

The `engine_withdraw` cross-contract call is dispatched to the stored connector account. The connector is the contract that actually holds and burns the NEP-141 ETH tokens on NEAR. There is no timelock, no minimum delay, and no two-step confirmation before the new connector takes effect.

The public NEAR entrypoint is exposed at: [3](#0-2) 

The `SetEthConnectorContractAccountArgs` struct confirms the parameter is a plain NEAR `AccountId` with no validation beyond ownership: [4](#0-3) 

### Impact Explanation
**Critical — Direct theft of user funds.**

The ETH connector contract holds all NEP-141 ETH tokens bridged to NEAR. When a user calls `withdraw`, the engine makes a cross-contract call to `engine_withdraw` on the stored connector account. If the owner has replaced the connector with a malicious NEAR contract, that contract:
- Receives the call containing `sender_id`, `recipient_address`, and `amount`
- Can accept the call without burning the user's NEP-141 tokens
- Retains the NEP-141 ETH tokens, effectively stealing them

The user's Aurora EVM balance is decremented by the connector's `engine_withdraw` logic, so the user loses both their Aurora balance and their bridged ETH.

### Likelihood Explanation
The owner can call `set_eth_connector_contract_account` in a single NEAR transaction that takes effect in the same block. On NEAR, transaction ordering within a block is deterministic and observable. The owner can observe a large pending `withdraw` transaction and submit `set_eth_connector_contract_account` in the same or preceding block to redirect the withdrawal. No special infrastructure is needed beyond owning the Aurora Engine account.

### Recommendation
Implement a timelock (minimum delay period) for `set_eth_connector_contract_account` and analogously for `factory_set_wnear_address`. Parameter changes should be staged and only executable after a mandatory delay, giving users time to observe and react to pending connector changes before they take effect.

### Proof of Concept
1. Owner observes a large user `withdraw` transaction in the NEAR mempool/block.
2. Owner calls `set_eth_connector_contract_account` with a malicious NEAR account ID that implements `engine_withdraw` to accept calls but not burn tokens.
3. The malicious connector account is stored immediately with no delay.
4. User's `withdraw` transaction executes; the engine calls `engine_withdraw` on the malicious connector.
5. The malicious connector steals the NEP-141 ETH tokens. The user receives nothing on Ethereum.

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

**File:** engine-types/src/parameters/connector.rs (L214-218)
```rust
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct SetEthConnectorContractAccountArgs {
    pub account: AccountId,
    pub withdraw_serialize_type: WithdrawSerializeType,
}
```
