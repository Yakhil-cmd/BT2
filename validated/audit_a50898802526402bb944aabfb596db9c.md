### Title
Missing Caller Authentication on `deploy_erc20_token` Allows Unauthorized NEP-141 → ERC-20 Mapping Registration - (File: engine/src/contract_methods/connector.rs)

### Summary

The `deploy_erc20_token` entrypoint performs no caller authentication. Any NEAR account can invoke it to deploy an ERC-20 contract in the Aurora EVM and register an authoritative NEP-141 → ERC-20 address mapping. The function's own inline comment acknowledges it "could be executed by the owner of the contract only," but no `require_owner_only` guard is present, making the privilege boundary entirely unenforced — a direct analog to the "running as root" class of missing privilege enforcement.

### Finding Description

`deploy_erc20_token` in `engine/src/contract_methods/connector.rs` only calls `require_running`, which checks the pause flag, and then immediately proceeds to deploy an ERC-20 and register the NEP-141 → ERC-20 mapping:

```
require_running(&state::get_state(&io)?)?;
// ... no require_owner_only, no assert_private_call, no whitelist check
engine::deploy_erc20_token(nep141, None, io, env, handler)?;
``` [1](#0-0) 

The `WithMetadata` branch carries an explicit comment that this should be owner-only, yet enforces nothing: [2](#0-1) 

Compare this to every other privileged mutative function in the codebase, which all call `require_owner_only` or `require_owner_and_running`: [3](#0-2) 

The NEAR entrypoint in `lib.rs` exposes this function with no additional guard: [4](#0-3) 

The underlying `engine::deploy_erc20_token` uses `predecessor_account_id` as the EVM sender and calls `engine.register_token(address, nep141)`, writing the canonical NEP-141 → ERC-20 mapping into contract storage: [5](#0-4) 

### Impact Explanation

The NEP-141 → ERC-20 mapping is the authoritative record used by `ft_on_transfer` to credit bridged tokens to the correct ERC-20 contract. An attacker who registers a mapping for a legitimate NEP-141 token (e.g., USDC, USDT) before the legitimate deployment causes all subsequent bridge deposits for that token to be credited to the attacker-registered ERC-20. If the `register_token` implementation permits overwriting an existing mapping, an attacker can redirect deposits away from an already-live ERC-20, permanently stranding the balances of existing holders in the old contract — a permanent fund freeze. Even if overwriting is blocked, pre-registration prevents the legitimate ERC-20 from ever being deployed under the correct mapping, trapping future bridge deposits in an unintended contract. [6](#0-5) 

### Likelihood Explanation

The attack requires only a standard NEAR account and knowledge of which NEP-141 tokens have not yet been registered. No privileged keys, no leaked secrets, and no governance capture are needed. The function is publicly callable on mainnet. The attacker's only cost is the NEAR gas for the transaction.

### Recommendation

Add `require_owner_only` (or `require_owner_and_running`) immediately after `require_running`, consistent with every other privileged function in the contract:

```rust
let state = state::get_state(&io)?;
require_running(&state)?;
require_owner_only(&state, &env.predecessor_account_id())?;
``` [7](#0-6) 

### Proof of Concept

1. Identify a NEP-141 token (e.g., `usdc.near`) that has not yet been registered in Aurora.
2. From any NEAR account (no owner key required), call `deploy_erc20_token` on the Aurora Engine contract with `nep141 = "usdc.near"`.
3. The call succeeds: a new ERC-20 is deployed in the Aurora EVM and the mapping `usdc.near → <attacker-deployed ERC-20>` is written to storage.
4. The legitimate operator's subsequent `deploy_erc20_token("usdc.near")` either fails (if `register_token` rejects duplicates) or overwrites the mapping (if it permits updates).
5. All users who bridge USDC from NEAR to Aurora now receive tokens in the attacker-registered ERC-20 rather than the intended contract, with no recourse for existing holders. [8](#0-7)

### Citations

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

**File:** engine/src/contract_methods/connector.rs (L112-131)
```rust
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
```

**File:** engine/src/contract_methods/connector.rs (L148-156)
```rust
                // Safe because these promises are read-only calls to the main engine contract
                // and this transaction could be executed by the owner of the contract only.
                let promise_args = PromiseWithCallbackArgs { base, callback };
                let promise_id = handler.promise_create_with_callback(&promise_args);

                handler.promise_return(promise_id);

                Ok(PromiseOrValue::Promise(promise_args))
            }
```

**File:** engine/src/contract_methods/mod.rs (L79-97)
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

pub fn require_owner_and_running(
    state: &state::EngineState,
    predecessor_account_id: &AccountId,
) -> Result<(), ContractError> {
    require_running(state)?;
    require_owner_only(state, predecessor_account_id)?;

    Ok(())
}
```

**File:** engine/src/lib.rs (L614-621)
```rust
    pub extern "C" fn deploy_erc20_token() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/engine.rs (L1349-1374)
```rust
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
```

**File:** engine/src/contract_methods/admin.rs (L104-120)
```rust
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
```
