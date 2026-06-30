### Title
Unprotected `new()` Initialization Allows Any Caller to Seize Engine Ownership — (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

The Aurora Engine's `new()` initialization function enforces a one-time-call guard but performs **no check on who the caller is**. Any NEAR account that calls `new()` before the legitimate deployer can set itself as `owner_id`, gaining full administrative control over the engine, including the ability to deploy arbitrary upgrade code and redirect bridge accounting.

---

### Finding Description

`engine/src/contract_methods/admin.rs` exposes the `new()` function as the engine's sole initialization entry point: [1](#0-0) 

The only guard present is:

```rust
if state::get_state(&io).is_ok() {
    return Err(b"ERR_ALREADY_INITIALIZED".into());
}
``` [2](#0-1) 

There is no `require_owner_only`, no `predecessor_account_id` check, and no hardcoded deployer address. The `owner_id` field is taken directly from the caller-supplied `NewCallArgs` input: [3](#0-2) 

This is exposed as a public WASM export in `engine/src/lib.rs`: [4](#0-3) 

---

### Impact Explanation

Whoever calls `new()` first controls `owner_id`. The owner account is the sole authorized caller for every critical administrative function:

- `upgrade()` — deploys arbitrary new contract bytecode to the engine account, enabling complete takeover of all bridged funds.
- `set_eth_connector_contract_account()` — redirects all ETH bridge operations (deposits, withdrawals) to an attacker-controlled connector.
- `attach_full_access_key()` — adds a full-access key to the engine account, giving permanent unrestricted control.
- `stage_upgrade()`, `set_owner()`, `factory_update()`, `factory_set_wnear_address()`, etc. [5](#0-4) [6](#0-5) 

An attacker who seizes ownership via `new()` can call `upgrade()` to deploy malicious bytecode, draining all ETH and ERC-20 tokens held by the engine. **Impact: Critical — direct theft of all user funds at rest.**

---

### Likelihood Explanation

On NEAR Protocol, a contract deployment transaction can include a `FunctionCall` action in the same batch, atomically deploying and initializing. If the Aurora Engine is deployed this way, there is no window. However:

1. If deployment and `new()` are submitted as separate transactions (a common operational mistake or CI/CD pattern), any NEAR account can observe the uninitialized contract and front-run the `new()` call.
2. NEAR does not have mempool-level front-running in the Ethereum sense, but block producers can reorder transactions within a block, and any account can submit a `new()` call in the same block as the deployment if they observe it.
3. The function is callable by any NEAR account with no restriction whatsoever — there is no hardcoded deployer address, no signature check, and no access list.

Likelihood: **Medium** — depends on deployment procedure, but the vulnerability is fully reachable by an unprivileged NEAR account with zero preconditions if the deployment is not atomic.

---

### Recommendation

Add a caller restriction to `new()`. The simplest fix is to require that `predecessor_account_id == current_account_id` (i.e., only a self-call, which is only possible from a batch action in the deployment transaction), or hardcode the expected deployer account using a compile-time constant analogous to the TypeScript templating approach described in the original report. At minimum, the function should verify:

```rust
if env.predecessor_account_id() != env.current_account_id() {
    return Err(b"ERR_NOT_ALLOWED".into());
}
```

This ensures `new()` can only be called as part of a deployment batch, not by an external account.

---

### Proof of Concept

1. Attacker observes that the Aurora Engine contract has been deployed (e.g., via NEAR indexer or block explorer) but `new()` has not yet been called (state is empty).
2. Attacker submits a NEAR transaction calling `new()` on the engine account with `owner_id = attacker.near` in the `NewCallArgs`.
3. `state::get_state(&io)` returns `Err` (no state yet), so the guard passes.
4. `state::set_state` writes attacker's account as `owner_id`.
5. Legitimate deployer's subsequent `new()` call fails with `ERR_ALREADY_INITIALIZED`.
6. Attacker calls `upgrade()` (now authorized as owner) with malicious bytecode that transfers all ETH balances to the attacker.
7. All user funds bridged to Aurora are stolen. [1](#0-0) [7](#0-6)

### Citations

**File:** engine/src/contract_methods/admin.rs (L55-88)
```rust
#[named]
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }

    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

    let initial_hashchain = args.initial_hashchain();
    let state: EngineState = args.into();

    if let Some(block_hashchain) = initial_hashchain {
        let block_height = env.block_height();
        let mut hashchain = Hashchain::new(
            state.chain_id,
            env.current_account_id(),
            block_height,
            block_hashchain,
        );

        hashchain.add_block_tx(
            block_height,
            function_name!(),
            &input,
            &[],
            &Bloom::default(),
        )?;
        crate::hashchain::save_hashchain(&mut io, &hashchain)?;
    }

    state::set_state(&mut io, &state)?;
    Ok(())
}
```

**File:** engine/src/contract_methods/admin.rs (L169-206)
```rust
pub fn upgrade<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;

    let input = io.read_input().to_vec();
    let (code, state_migration_gas) = match UpgradeParams::try_from_slice(&input) {
        Ok(args) => (
            args.code,
            args.state_migration_gas
                .map_or(GAS_FOR_STATE_MIGRATION, NearGas::new),
        ),
        Err(_) => (input, GAS_FOR_STATE_MIGRATION), // Backward compatibility
    };

    let target_account_id = env.current_account_id();
    let batch = PromiseBatchAction {
        target_account_id,
        actions: vec![
            PromiseAction::DeployContract { code },
            PromiseAction::FunctionCall {
                name: "state_migration".to_string(),
                args: vec![],
                attached_yocto: ZERO_YOCTO,
                gas: state_migration_gas,
            },
        ],
    };
    let promise_id = handler.promise_create_batch(&batch);

    handler.promise_return(promise_id);

    Ok(())
}
```

**File:** engine/src/lib.rs (L76-83)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn new() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::new(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
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
