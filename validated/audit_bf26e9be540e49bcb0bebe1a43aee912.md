### Title
Unrestricted `deploy_erc20_token` Allows Any Caller to Register Arbitrary NEP-141 → ERC-20 Mappings - (File: `engine/src/contract_methods/connector.rs`)

### Summary
The `deploy_erc20_token` function in the Aurora Engine connector lacks any caller access control. The code's own comment explicitly states the function "could be executed by the owner of the contract only," yet no `require_owner_only` guard is present. Any unprivileged NEAR account can invoke this entrypoint, deploy a new ERC-20 contract inside the EVM, and register an arbitrary NEP-141 → ERC-20 address mapping in the engine's storage.

### Finding Description
`deploy_erc20_token` is the NEAR-level entrypoint that bridges a NEP-141 fungible token into Aurora by deploying an `EvmErc20` contract and writing the canonical NEP-141 ↔ ERC-20 address mapping via `engine::register_token`.

The function body performs only a liveness check (`require_running`) before proceeding: [1](#0-0) 

No `require_owner_only` call appears anywhere in the function. The comment inside the `WithMetadata` branch acknowledges the intended restriction but does not enforce it: [2](#0-1) 

Compare this with every other sensitive admin function in the same codebase, all of which call `require_owner_only` before acting: [3](#0-2) 

The public WASM entrypoint in `lib.rs` passes control directly to `connector::deploy_erc20_token` with no additional gate: [4](#0-3) 

The downstream `engine::deploy_erc20_token` then deploys the ERC-20 bytecode and calls `engine.register_token(address, nep141)`, writing the mapping unconditionally: [5](#0-4) 

The `EvmErc20.mint` function is `onlyAdmin`, where admin is set to the Aurora Engine contract address at deploy time: [6](#0-5) 

This means the newly deployed ERC-20 contract is fully controlled by the Aurora Engine, and the engine will mint into it whenever `ft_on_transfer` is called with the registered NEP-141 as predecessor.

### Impact Explanation
An attacker who calls `deploy_erc20_token` with the account ID of a **legitimately bridged NEP-141 token** (one that already has an existing ERC-20 mapping and live user balances) causes the engine to deploy a second ERC-20 contract and overwrite the canonical mapping. After the overwrite:

- `ft_on_transfer` from the NEP-141 contract mints into the **new** ERC-20, not the old one.
- Holders of the **old** ERC-20 tokens cannot bridge back to NEAR because `get_erc20_from_nep141` now returns the new address; their tokens are permanently stranded.
- The bridge accounting is corrupted: NEP-141 supply on NEAR is not matched by any reachable ERC-20 supply on Aurora.

This constitutes **permanent freezing of user funds** (Critical) and **bridge insolvency** (Critical).

### Likelihood Explanation
- No privileged access is required; any NEAR account with enough gas can call `deploy_erc20_token`.
- The target NEP-141 account IDs of all bridged tokens are publicly observable on-chain.
- The attack is a single NEAR transaction with a known, well-formed Borsh-encoded argument.
- There is no rate limit, deposit requirement, or whitelist protecting the entrypoint.

### Recommendation
Add `require_owner_only` (or a dedicated deployer role) at the top of `deploy_erc20_token`, consistent with every other privileged function in the contract:

```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
+       require_owner_only(&state, &env.predecessor_account_id())?;
        ...
    })
}
``` [7](#0-6) 

### Proof of Concept
1. Identify a live bridged NEP-141 token (e.g., `usdt.tether-token.near`) whose ERC-20 mapping is already registered in the Aurora Engine.
2. From any NEAR account, call:
   ```
   aurora.deploy_erc20_token(
       DeployErc20TokenArgs::Legacy("usdt.tether-token.near")
   )
   ```
3. The engine deploys a fresh `EvmErc20` contract at a new address and calls `register_token(new_address, "usdt.tether-token.near")`, overwriting the stored mapping.
4. All subsequent `ft_on_transfer` calls from `usdt.tether-token.near` mint into the new ERC-20.
5. Existing holders of the original ERC-20 USDT on Aurora cannot exit to NEAR (the bridge lookup returns the new address); their funds are permanently frozen. [8](#0-7) [9](#0-8)

### Citations

**File:** engine/src/contract_methods/connector.rs (L61-109)
```rust
#[named]
pub fn ft_on_transfer<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();
        let mut engine: Engine<_, _> = Engine::new(
            predecessor_address(&predecessor_account_id),
            current_account_id.clone(),
            io,
            env,
        )?;

        sdk::log!("Call ft_on_transfer");

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

        #[allow(clippy::used_underscore_binding)]
        let amount_to_return = if let Err(_err) = &result {
            sdk::log!("Error in ft_on_transfer: {_err:?}");
            // An error occurred, so we need to return the amount of tokens to the sender.
            args.amount.as_u128()
        } else {
            // Everything is ok, so return 0.
            0
        };

        let output = crate::prelude::format!("\"{amount_to_return}\"");
        io.return_output(output.as_bytes());

        // In case of an error, we just return Ok(None) to avoid a panic in the contract. It's ok
        // because in case of an error, we already returned the amount of tokens to the sender.
        Ok(result.unwrap_or(None))
    })
}
```

**File:** engine/src/contract_methods/connector.rs (L111-125)
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
```

**File:** engine/src/contract_methods/connector.rs (L148-151)
```rust
                // Safe because these promises are read-only calls to the main engine contract
                // and this transaction could be executed by the owner of the contract only.
                let promise_args = PromiseWithCallbackArgs { base, callback };
                let promise_id = handler.promise_create_with_callback(&promise_args);
```

**File:** engine/src/contract_methods/admin.rs (L103-121)
```rust
#[named]
pub fn set_owner<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;

        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;

        let args: SetOwnerArgs = io.read_input_borsh()?;
        if state.owner_id == args.new_owner {
            return Err(errors::ERR_SAME_OWNER.into());
        }

        state.owner_id = args.new_owner;
        state::set_state(&mut io, &state)?;

        Ok(())
    })
}
```

**File:** engine/src/lib.rs (L613-621)
```rust
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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L49-51)
```text
    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
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
