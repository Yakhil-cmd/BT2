### Title
Unprotected `new` Initialization Function Allows Attacker to Seize Engine Ownership - (File: `engine/src/contract_methods/admin.rs`)

### Summary

The `new` function that initializes the Aurora Engine's state has no caller access control. Any NEAR account can call it before the legitimate deployer does, setting an attacker-controlled `owner_id` and `key_manager`. Because the owner account controls upgrade, key management, and full-access-key attachment, this leads to complete engine takeover and potential theft of all bridged funds.

### Finding Description

The `new` function in `engine/src/contract_methods/admin.rs` is the sole initialization entry point for the engine's persistent `EngineState`. Its only guard is a re-initialization check:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // ... reads args, sets state
    state::set_state(&mut io, &state)?;
}
``` [1](#0-0) 

There is no check on `env.predecessor_account_id()`. The function accepts caller-supplied `NewCallArgs` which directly populate `EngineState::owner_id` and `EngineState::key_manager`: [2](#0-1) 

The `EngineState` produced from these args is written unconditionally: [3](#0-2) 

The public NEAR entrypoint `new()` in `lib.rs` delegates directly to this function with no additional guard: [4](#0-3) 

The deployment pattern used in practice (and shown in test utilities) deploys the contract wasm in one transaction and calls `new` in a separate subsequent transaction, creating an exploitable window: [5](#0-4) 

### Impact Explanation

An attacker who calls `new` first with their own `owner_id` becomes the engine owner. The owner account is the sole authorized caller for:

- `attach_full_access_key` — adds a full-access key to the engine's NEAR account, granting complete account control including withdrawal of all NEAR and bridged ETH balances
- `upgrade` / `stage_upgrade` — deploys arbitrary replacement contract code
- `set_owner`, `set_key_manager`, `pause_contract`, `factory_update`, `factory_set_wnear_address` [6](#0-5) [7](#0-6) 

With a full-access key on the engine account, the attacker can drain all ETH held in the bridge, redirect all future deposits, or permanently freeze the protocol. This satisfies **Critical: Direct theft of user funds** and **Critical: Permanent freezing of funds**.

### Likelihood Explanation

NEAR transactions are publicly observable. An attacker monitoring the NEAR network can detect the contract deployment transaction (which does not call `new`) and immediately submit their own `new` call in the next block. The window exists whenever deployment and initialization are performed in separate transactions, which is the standard pattern shown in the codebase. No special privileges or leaked keys are required — only the ability to submit a NEAR transaction.

### Recommendation

Add a caller check inside `new` so that only the contract account itself (i.e., `env.current_account_id() == env.predecessor_account_id()`) or a pre-committed deployer address can initialize the engine. The most robust fix is to perform contract deployment and the `new` call atomically in a single NEAR batch transaction, which eliminates the window entirely. Additionally, add an explicit `predecessor_account_id` guard:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // Only the contract account itself may initialize (batch deploy+init pattern)
    if env.predecessor_account_id() != env.current_account_id() {
        return Err(b"ERR_NOT_ALLOWED".into());
    }
    // ...
}
```

### Proof of Concept

1. Deployer submits a NEAR transaction deploying the Aurora Engine wasm to account `aurora`.
2. Attacker observes this transaction on-chain (NEAR transactions are public).
3. Before the deployer's follow-up `new` call lands, attacker submits:
   ```
   aurora.new({
     chain_id: <valid>,
     owner_id: "attacker.near",
     upgrade_delay_blocks: 0,
     key_manager: "attacker.near",
     initial_hashchain: None
   })
   ```
4. Attacker's `new` call succeeds because `state::get_state` returns `Err` (state not yet set).
5. `EngineState { owner_id: "attacker.near", key_manager: "attacker.near", ... }` is written to storage.
6. Deployer's subsequent `new` call fails with `ERR_ALREADY_INITIALIZED`.
7. Attacker calls `attach_full_access_key` (owner-only) to add their key to the `aurora` account.
8. With a full-access key, attacker withdraws all NEAR balance and deploys malicious contract code, stealing all bridged ETH. [1](#0-0) [6](#0-5)

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

**File:** engine-types/src/parameters/engine.rs (L100-115)
```rust
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct NewCallArgsV4 {
    /// Chain id, according to the EIP-115 / ethereum-lists spec.
    #[serde(with = "chain_id_deserialize")]
    pub chain_id: RawU256,
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
    /// Relayer keys manager.
    pub key_manager: AccountId,
    /// Initial value of the hashchain.
    /// If none is provided then the hashchain will start disabled.
    pub initial_hashchain: Option<RawH256>,
}
```

**File:** engine/src/state.rs (L184-194)
```rust
impl From<NewCallArgsV4> for EngineState {
    fn from(args: NewCallArgsV4) -> Self {
        Self {
            chain_id: args.chain_id,
            owner_id: args.owner_id,
            upgrade_delay_blocks: args.upgrade_delay_blocks,
            is_paused: false,
            key_manager: Some(args.key_manager),
        }
    }
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

**File:** engine-tests-connector/src/utils.rs (L91-168)
```rust
        let engine_contract_bytes = get_engine_contract();
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
