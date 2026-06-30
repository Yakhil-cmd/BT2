### Title
Unprivileged Caller Can Register Any NEP-141 Token via `deploy_erc20_token`, Blocking Legitimate Bridge Setup - (`engine/src/contract_methods/connector.rs`)

---

### Summary

The `deploy_erc20_token` function in the Aurora Engine is callable by **any NEAR account** with no access control. The function deploys an ERC-20 mirror contract in the EVM and permanently registers the NEP-141 → ERC-20 mapping. An attacker can front-run the admin's legitimate call to register any NEP-141 token with an ERC-20 address of the attacker's choosing (determined by the attacker's EVM nonce), permanently blocking the admin from ever registering that token at the correct address.

---

### Finding Description

`deploy_erc20_token` in `engine/src/contract_methods/connector.rs` performs only a liveness check (`require_running`) and no caller authorization:

```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;   // ← only check
        // no require_owner_only, no assert_private_call
        ...
        engine::deploy_erc20_token(nep141, None, io, env, handler)?;
``` [1](#0-0) 

The code's own comment in the `WithMetadata` branch acknowledges the intended restriction but does not enforce it:

```
// Safe because these promises are read-only calls to the main engine contract
// and this transaction could be executed by the owner of the contract only.
``` [2](#0-1) 

Contrast this with other sensitive functions in the same file that correctly enforce caller restrictions:

- `mirror_erc20_token` calls `require_owner_only` [3](#0-2) 
- `set_eth_connector_contract_account` calls `require_owner_only` or `assert_private_call` [4](#0-3) 
- `deploy_erc20_token_callback` calls `env.assert_private_call()` [5](#0-4) 

The `deploy_erc20_token` WASM export is a public entry point with no restriction: [6](#0-5) 

Inside `engine::deploy_erc20_token`, the EVM origin is set to `predecessor_address(&predecessor_account_id)`, meaning the ERC-20 is deployed at an address determined by the **attacker's** NEAR account ID and their EVM nonce: [7](#0-6) 

The NEP-141 → ERC-20 mapping is then permanently written via `engine.register_token(address, nep141)`.

---

### Impact Explanation

**Impact: Permanent freezing of funds / permanent DoS of the token bridge for any NEP-141 token.**

1. An attacker calls `deploy_erc20_token` for a target NEP-141 token (e.g., `usdc.near`) before the admin does.
2. The ERC-20 is deployed at an address derived from the attacker's NEAR account ID and nonce, and the NEP-141 → ERC-20 mapping is permanently written to storage.
3. The admin can never register the same NEP-141 token to a different ERC-20 address, because `register_token` will reject a duplicate registration.
4. All subsequent `ft_on_transfer` deposits for that NEP-141 token will mint tokens to the attacker-chosen ERC-20 address.
5. The attacker can repeat this for every NEP-141 token, rendering the entire bridge unusable for new token listings.

This matches the **Permanent freezing of funds** and **Critical** impact tier: users who deposit NEP-141 tokens after the attacker's registration will receive ERC-20 tokens at an address the admin did not intend, and the admin cannot correct the mapping.

---

### Likelihood Explanation

- The attack requires only a single NEAR transaction with no special privileges.
- The attacker only needs to know the NEP-141 account ID of a token the admin intends to bridge (publicly observable from governance discussions, announcements, or mempool monitoring).
- The attack is cheap (only NEAR gas) and can be repeated for every new token listing.
- No front-running is strictly required: the attacker can call `deploy_erc20_token` at any time before the admin does.

---

### Recommendation

Add `require_owner_only` (or an equivalent authorized-caller check) at the top of `deploy_erc20_token`, consistent with the pattern used in `mirror_erc20_token` and other sensitive connector functions:

```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?; // ADD THIS
        ...
    })
}
``` [8](#0-7) 

---

### Proof of Concept

1. Admin announces intent to bridge `usdc.near` to Aurora.
2. Attacker submits a NEAR transaction calling `deploy_erc20_token` on the Aurora Engine contract with `nep141 = "usdc.near"`.
3. The call succeeds (only `require_running` is checked). An ERC-20 is deployed at address `CREATE(attacker_evm_address, attacker_nonce)` and the mapping `usdc.near → attacker_erc20_addr` is written to storage.
4. Admin subsequently calls `deploy_erc20_token` for `usdc.near`. The call fails because `register_token` rejects the duplicate NEP-141 registration.
5. All `ft_on_transfer` calls from the USDC NEP-141 contract now mint tokens to the attacker-chosen ERC-20 address. The admin cannot correct this mapping.
6. The attacker repeats for every planned token listing, permanently blocking the bridge for all new tokens. [9](#0-8) [10](#0-9)

### Citations

**File:** engine/src/contract_methods/connector.rs (L111-159)
```rust
#[named]
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
            }
            DeployErc20TokenArgs::WithMetadata(nep141) => {
                let args = borsh::to_vec(&nep141).map_err(|_| errors::ERR_SERIALIZE)?;
                let base = PromiseCreateArgs {
                    target_account_id: nep141,
                    method: "ft_metadata".to_string(),
                    args: vec![],
                    attached_balance: ZERO_YOCTO,
                    attached_gas: READ_PROMISE_ATTACHED_GAS,
                };
                let callback = PromiseCreateArgs {
                    target_account_id: env.current_account_id(),
                    method: "deploy_erc20_token_callback".to_string(),
                    args,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: DEPLOY_ERC20_TOKEN_CALLBACK_ATTACHED_GAS,
                };
                // Safe because these promises are read-only calls to the main engine contract
                // and this transaction could be executed by the owner of the contract only.
                let promise_args = PromiseWithCallbackArgs { base, callback };
                let promise_id = handler.promise_create_with_callback(&promise_args);

                handler.promise_return(promise_id);

                Ok(PromiseOrValue::Promise(promise_args))
            }
        }
    })
}
```

**File:** engine/src/contract_methods/connector.rs (L167-169)
```rust
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        env.assert_private_call()?;
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

**File:** engine/src/contract_methods/connector.rs (L456-463)
```rust
pub fn mirror_erc20_token<I: IO + Env + Copy, H: PromiseHandler>(
    io: I,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    // TODO: Add an admin access list of accounts allowed to do it.
    require_owner_only(&state, &io.predecessor_account_id())?;
```

**File:** engine/src/lib.rs (L612-621)
```rust
    /// Deploy ERC20 token mapped to a NEP141
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_erc20_token() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/engine.rs (L1339-1375)
```rust
/// Used to bridge NEP-141 tokens from NEAR to Aurora. On Aurora the NEP-141 becomes an ERC-20.
pub fn deploy_erc20_token<I: IO + Copy, E: Env, P: PromiseHandler>(
    nep141: AccountId,
    metadata: Option<Erc20Metadata>,
    io: I,
    env: &E,
    handler: &mut P,
) -> Result<Address, DeployErc20Error> {
    let current_account_id = env.current_account_id();
    let input = setup_deploy_erc20_input(&current_account_id, metadata);
    let mut engine: Engine<_, _> = Engine::new(
        aurora_engine_sdk::types::near_account_to_evm_address(
            env.predecessor_account_id().as_bytes(),
        ),
        current_account_id,
        io,
        env,
    )
    .map_err(DeployErc20Error::State)?;

    let address = match engine.deploy_code_with_input(input, None, handler) {
        Ok(result) => match result.status {
            TransactionStatus::Succeed(ret) => {
                Address::new(H160(ret.as_slice().try_into().unwrap()))
            }
            other => return Err(DeployErc20Error::Failed(other)),
        },
        Err(e) => return Err(DeployErc20Error::Engine(e)),
    };

    sdk::log!("Deployed ERC-20 in Aurora at: {:#?}", address);
    engine
        .register_token(address, nep141)
        .map_err(DeployErc20Error::Register)?;

    Ok(address)
}
```

**File:** engine/src/contract_methods/mod.rs (L79-87)
```rust
pub fn require_owner_only(
    state: &state::EngineState,
    predecessor_account_id: &AccountId,
) -> Result<(), ContractError> {
    if &state.owner_id != predecessor_account_id {
        return Err(errors::ERR_NOT_ALLOWED.into());
    }
    Ok(())
}
```
