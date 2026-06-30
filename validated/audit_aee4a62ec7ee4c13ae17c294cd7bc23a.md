### Title
Unguarded `new()` Initializer Allows Any Caller to Seize Engine Ownership — (`File: engine/src/contract_methods/admin.rs`)

---

### Summary

The Aurora Engine's `new()` initializer performs no caller check. Any NEAR account can call it before the legitimate deployer does, supplying an arbitrary `owner_id`. This gives the attacker full administrative control over the engine, enabling contract upgrades, connector redirection, and ultimately theft or permanent freeze of all bridged funds.

---

### Finding Description

`new()` in `engine/src/contract_methods/admin.rs` is the sole initialization entry point for the engine's `EngineState`. It guards against double-initialization with a state-existence check, but it performs **no check on who is calling it**:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input)...;
    // ...
    state::set_state(&mut io, &state)?;   // owner_id comes entirely from args
    Ok(())
}
``` [1](#0-0) 

`env.predecessor_account_id()` is never consulted. The `owner_id` written into `EngineState` is taken verbatim from the caller-supplied `NewCallArgs`: [2](#0-1) 

The public WASM entrypoint exposes this function with no additional guard: [3](#0-2) 

The workspace deployment helper (`EngineContractBuilder::deploy_and_init`) issues the WASM deploy and the `new()` call as **two separate awaited transactions**, not as a single atomic NEAR batch action: [4](#0-3) 

This creates the same two-step window described in the reference report: between the `DeployContract` action landing on-chain and the `new()` call being confirmed, the contract is live but uninitialized, and any NEAR account can race to call `new()` first.

---

### Impact Explanation

Whoever calls `new()` first writes the `owner_id`. All privileged operations — `upgrade`, `set_eth_connector_contract_account`, `pause_contract`, `set_owner`, `set_key_manager` — are gated solely on `owner_id == predecessor_account_id`: [5](#0-4) 

An attacker who wins the race can:

1. **Call `set_eth_connector_contract_account`** to redirect the engine to a malicious ETH connector, stealing all bridged ETH deposits — **Critical: direct theft of user funds**.
2. **Call `upgrade`** to deploy arbitrary WASM — **Critical: permanent fund freeze or theft**.
3. **Call `pause_contract`** to halt all user operations — **High: temporary fund freeze**.

The legitimate deployer's subsequent `new()` call will fail with `ERR_ALREADY_INITIALIZED`, requiring a full redeployment to a new account.

---

### Likelihood Explanation

NEAR transactions are publicly visible on-chain immediately after they are included in a block. An attacker monitoring the NEAR RPC or block explorer for a `DeployContract` action targeting the `aurora` account can submit a `new()` call in the very next block. NEAR block times are ~1 second, giving a narrow but real window. The attack requires no special privilege — any funded NEAR account suffices. The only mitigation in practice is if the deployer uses a single atomic NEAR batch action combining `DeployContract` + `FunctionCall(new)`, but the code itself enforces nothing of the sort.

---

### Recommendation

Add a caller check at the top of `new()` that requires `env.predecessor_account_id() == env.current_account_id()`. In NEAR, only the contract account itself (via a batch action or a self-call) should be permitted to initialize its own state:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if env.predecessor_account_id() != env.current_account_id() {
        return Err(b"ERR_NOT_ALLOWED".into());
    }
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // ...
}
```

This ensures that `new()` can only be invoked as part of a batch transaction signed by the contract account's key, making deployment and initialization atomic and eliminating the front-running window.

---

### Proof of Concept

1. Deployer broadcasts a NEAR transaction containing only a `DeployContract` action targeting `aurora`.
2. Attacker observes the transaction land in block N.
3. In block N+1, attacker submits:
   ```
   aurora.new({
     chain_id: <legitimate chain id>,
     owner_id: "attacker.near",
     upgrade_delay_blocks: 0,
     key_manager: "attacker.near",
     initial_hashchain: null
   })
   ```
4. `state::get_state` returns `Err` (not yet initialized), so the guard passes.
5. `EngineState { owner_id: "attacker.near", ... }` is written to storage.
6. Deployer's own `new()` call arrives and fails with `ERR_ALREADY_INITIALIZED`.
7. Attacker calls `set_eth_connector_contract_account` pointing to a malicious contract, then waits for users to deposit ETH — all deposits are stolen. [1](#0-0) [6](#0-5)

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

**File:** engine/src/state.rs (L207-224)
```rust
/// Gets the state from storage, if it exists otherwise it will error.
pub fn get_state<I: IO + Copy>(io: &I) -> Result<EngineState, EngineStateError> {
    io.read_storage(&bytes_to_key(KeyPrefix::Config, STATE_KEY))
        .map_or_else(
            || Err(EngineStateError::NotFound),
            |bytes| EngineState::try_from_slice(&bytes.to_vec(), io),
        )
}

/// Saves state into the storage. Does not return the previous state.
pub fn set_state<I: IO>(io: &mut I, state: &EngineState) -> Result<(), EngineStateError> {
    io.write_storage(
        &bytes_to_key(KeyPrefix::Config, STATE_KEY),
        &state.borsh_serialize()?,
    );

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

**File:** engine-workspace/src/lib.rs (L107-127)
```rust
        let contract = account
            .deploy(
                &self
                    .code
                    .ok_or_else(|| anyhow::anyhow!("WASM wasn't set"))?,
            )
            .await?;
        let engine = EngineContract {
            account,
            contract,
            public_key,
            node,
        };

        engine
            .new(self.chain_id, self.owner_id, self.upgrade_delay_blocks)
            .transact()
            .await
            .map_err(|e| anyhow::anyhow!("Error while initialize aurora contract: {e}"))?;

        Ok(engine)
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
