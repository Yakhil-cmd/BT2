### Title
Unprotected `new` Initialization Allows Anyone to Front-Run Engine Setup and Seize Ownership — (File: `engine/src/contract_methods/admin.rs`)

### Summary

The `new` function that initializes the Aurora Engine state has no access control. Any NEAR account can call it before the legitimate deployer does. Because the function permanently rejects subsequent calls once state is written, a front-runner who calls `new` first becomes the engine's `owner_id` and can subsequently invoke privileged methods — including `attach_full_access_key` — to gain full control of the engine account and all funds it holds.

### Finding Description

`engine/src/contract_methods/admin.rs` exposes `new` as a public NEAR contract method with no caller restriction:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input)...;
    ...
    state::set_state(&mut io, &state)?;
    Ok(())
}
``` [1](#0-0) 

The only guard is the already-initialized check on line 57. There is no check on `env.predecessor_account_id()`. The NEAR-level entry point in `lib.rs` also adds no restriction:

```rust
#[unsafe(no_mangle)]
pub extern "C" fn new() {
    let io = Runtime;
    let env = Runtime;
    contract_methods::admin::new(io, &env)
        .map_err(ContractError::msg)
        .sdk_unwrap();
}
``` [2](#0-1) 

The `owner_id` stored in `EngineState` is taken directly from the attacker-supplied `NewCallArgs` input, not from `env.predecessor_account_id()`. An attacker who calls `new` first can write any account — including their own — as `owner_id`.

The deployment pattern used in the project's own test utilities separates the `deploy` and `new` calls into two distinct transactions, creating an exploitable window:

```rust
let engine_contract = engine.deploy(&engine_contract_bytes).await?.into_result()?;
// ... separate transaction:
let res = engine_contract
    .call("new")
    .args_borsh((chain_id, engine_contract.id(), engine_contract.id(), 1_u64))
    ...
    .transact()
    .await?;
``` [3](#0-2) 

Once the attacker's `new` call succeeds, the legitimate deployer's `new` call returns `ERR_ALREADY_INITIALIZED` and the engine is permanently under attacker control.

### Impact Explanation

**Critical — Direct theft of user funds / permanent freeze.**

With attacker-controlled `owner_id`, the attacker can immediately call `attach_full_access_key`:

```rust
pub fn attach_full_access_key<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I, env: &E, handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;
    ...
    let promise_id = handler.promise_create_batch(&promise);
    handler.promise_return(promise_id);
    Ok(())
}
``` [4](#0-3) 

Adding a full access key to the engine's NEAR account gives the attacker unrestricted ability to drain all NEAR and bridged token balances held by the contract. Additionally, the attacker can call `pause_contract` to freeze the engine for all users, or call `factory_update` to replace the XCC router bytecode with malicious code.

### Likelihood Explanation

**High.** The project's own integration test utilities deploy the contract and call `new` in separate transactions (shown above). Any production deployment script that follows the same pattern — or any deployment where the `new` call is not bundled atomically with the `DeployContract` action in a single NEAR batch — is exploitable. An attacker only needs to monitor the NEAR transaction pool for a `DeployContract` action targeting the engine account and immediately submit a `new` call with attacker-controlled args.

### Recommendation

Add a predecessor check inside `new` so that only the contract account itself (i.e., the deployer who submitted the batch) can initialize it:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
+   if env.predecessor_account_id() != env.current_account_id() {
+       return Err(b"ERR_NOT_ALLOWED".into());
+   }
    ...
}
```

Alternatively, enforce that `new` is always called in the same batch as `DeployContract` by documenting and enforcing this in deployment scripts, and adding the predecessor check as a defense-in-depth measure.

### Proof of Concept

1. Attacker monitors the NEAR transaction pool.
2. Deployer submits `DeployContract` for the Aurora Engine WASM to account `aurora`.
3. Before the deployer's separate `new` call lands, attacker submits:
   ```
   aurora.new({
     chain_id: <any>,
     owner_id: "attacker.near",
     upgrade_delay_blocks: 0
   })
   ```
4. Attacker's `new` call executes first; `EngineState { owner_id: "attacker.near", ... }` is written to storage.
5. Deployer's `new` call returns `ERR_ALREADY_INITIALIZED` and reverts.
6. Attacker calls `aurora.attach_full_access_key({ public_key: <attacker_key> })` — passes `require_owner_only` because `predecessor == "attacker.near" == state.owner_id`.
7. Attacker's key is added to the `aurora` NEAR account; attacker has full control and can drain all funds. [1](#0-0) [2](#0-1)

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

**File:** engine/src/contract_methods/admin.rs (L483-512)
```rust
pub fn attach_full_access_key<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;

    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;

    let public_key = serde_json::from_slice::<FullAccessKeyArgs>(&io.read_input().to_vec())
        .map(|args| args.public_key)
        .map_err(|_| errors::ERR_JSON_DESERIALIZE)?;
    let current_account_id = env.current_account_id();
    let action = PromiseAction::AddFullAccessKey {
        public_key,
        nonce: 0, // not actually used - depends on block height
    };
    let promise = PromiseBatchAction {
        target_account_id: current_account_id,
        actions: vec![action],
    };
    // SAFETY: This action is dangerous because it adds a new full access key (FAK) to the Engine account.
    // However, it is safe to do so here because of the `require_owner_only` check above; only the
    // (trusted) owner account can add a new FAK.
    let promise_id = handler.promise_create_batch(&promise);

    handler.promise_return(promise_id);

    Ok(())
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

**File:** engine-tests-connector/src/utils.rs (L92-168)
```rust
        let engine_contract = engine.deploy(&engine_contract_bytes).await?.into_result()?;
        let eth_connector_contract = eth_connector
            .deploy(
                CONTRACT_WASM
                    .get_or_try_init(|| download_and_extract_wasm(CONNECTOR_URL, WASM_FILE_NAME))
                    .await?,
            )
            .await?
            .into_result()?;

        Ok((engine_contract, eth_connector_contract, controller_account))
    }

    pub async fn new() -> anyhow::Result<Self> {
        Self::new_contract(None).await
    }

    pub async fn new_with_owner(owner: &str) -> anyhow::Result<Self> {
        Self::new_contract(Some(owner)).await
    }

    async fn new_contract(owner: Option<&str>) -> anyhow::Result<Self> {
        let (engine_contract, eth_connector_contract, controller_account) =
            Self::deploy_contracts().await?;

        let owner = if let Some(owner) = owner {
            Some(
                controller_account
                    .create_subaccount(owner)
                    .initial_balance(NearToken::from_near(15))
                    .transact()
                    .await?
                    .into_result()?,
            )
        } else {
            None
        };

        let metadata = FungibleTokenMetadata::default();
        // Init eth-connector
        let metadata = json!({
            "spec": metadata.spec,
            "name": metadata.name,
            "symbol": metadata.symbol,
            "icon": metadata.icon,
            "reference": metadata.reference,
            "decimals": metadata.decimals,
        });
        let res = eth_connector_contract
            .call("new")
            .args_json(json!({
                "metadata": metadata,
                "aurora_engine_account_id": engine_contract.id(),
                "owner_id": owner.as_ref().map_or_else(|| engine_contract.id(), |owner| owner.id()),
                "controller": controller_account.id(),
            }))
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success());

        let result = eth_connector_contract
            .call("pa_unpause_feature")
            .args_json(json!({ "key": "ALL" }))
            .max_gas()
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");

        let chain_id = [0u8; 32];
        let res = engine_contract
            .call("new")
            .args_borsh((chain_id, engine_contract.id(), engine_contract.id(), 1_u64))
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success());
```
