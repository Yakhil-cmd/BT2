### Title
Unprotected `new` Initialization Function Allows Any Caller to Seize Aurora Engine Ownership — (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

The Aurora Engine's `new` function, which initializes the engine state including the `owner_id`, has no caller restriction. Any NEAR account can call it before the legitimate deployer does, setting themselves as the owner and gaining complete administrative control over the engine. This is the direct NEAR-protocol analog of the reported Solidity unprotected `initialize()` vulnerability.

---

### Finding Description

The `new` function in `engine/src/contract_methods/admin.rs` is the sole initialization entry point for the Aurora Engine. It sets the `EngineState`, which includes the `owner_id` field that gates all privileged operations (upgrade, pause, set_owner, key management, etc.).

The function's only guard is a state-existence check:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input)...;
    let state: EngineState = args.into();
    state::set_state(&mut io, &state)?;
    Ok(())
}
``` [1](#0-0) 

There is **no check on `env.predecessor_account_id()`**. Any account that calls `new` before state is written becomes the effective owner.

The workspace deployment helper confirms that deployment and initialization are performed as **two separate transactions**, not an atomic batch:

```rust
let contract = account.deploy(&self.code...).await?;
// ...
engine.new(self.chain_id, self.owner_id, self.upgrade_delay_blocks)
    .transact()
    .await...
``` [2](#0-1) 

This creates a window — at minimum one NEAR block (~1 second) — between contract deployment and initialization, during which any observer can call `new` with attacker-controlled arguments.

The `EngineState` written by `new` includes `owner_id`, which is the account authorized to call `upgrade`, `stage_upgrade`, `set_owner`, `pause_contract`, `set_key_manager`, and `attach_full_access_key`: [3](#0-2) 

All privileged methods enforce `require_owner_only`, which compares `state.owner_id` against `predecessor_account_id`: [4](#0-3) 

The `new` entrypoint is exported as a public WASM function with no NEAR-runtime-level access control: [5](#0-4) 

---

### Impact Explanation

If an attacker front-runs `new`:

- They become `owner_id` of the Aurora Engine.
- They can call `upgrade` to deploy arbitrary malicious WASM, replacing the engine entirely.
- They can call `stage_upgrade` + `deploy_upgrade` to overwrite the contract.
- They can call `attach_full_access_key` to add a full-access key to the `aurora` account, giving permanent on-chain control.
- All bridged ETH and ERC-20 tokens held by the engine are at risk of direct theft.
- All user funds can be permanently frozen.

**Impact class: Critical — direct theft of all user funds and permanent fund freeze.** [6](#0-5) 

---

### Likelihood Explanation

- The Aurora Engine deployment on NEAR mainnet is a public, observable event.
- Any account monitoring the chain can detect the moment the WASM is deployed (before `new` is called) and immediately submit a competing `new` transaction.
- NEAR block time is ~1 second; the attacker has at least one full block to act.
- The attack requires no special privileges, no leaked keys, and no social engineering — only the ability to submit a NEAR transaction.
- This is a one-time opportunity, but the catastrophic impact makes even low-probability exploitation unacceptable.

---

### Recommendation

Perform deployment and initialization **atomically** in a single NEAR batch transaction:

```
BatchTransaction on aurora:
  Action 1: DeployContract { code: engine_wasm }
  Action 2: FunctionCall { method: "new", args: init_args }
```

This is the NEAR-native equivalent of OpenZeppelin's `_disableInitializers()` in a constructor — it eliminates the window between deployment and initialization entirely. Alternatively, add a predecessor check inside `new` that restricts the caller to the contract account itself (i.e., `env.predecessor_account_id() == env.current_account_id()`), enforcing that only a self-call (from a batch) can initialize the engine.

---

### Proof of Concept

1. Monitor NEAR mainnet for a transaction deploying WASM to the `aurora` account.
2. Before the deployer's `new` call lands, submit:
   ```
   near call aurora new \
     '{"chain_id": [...], "owner_id": "attacker.near", "upgrade_delay_blocks": 0}' \
     --accountId attacker.near
   ```
3. `state::get_state` returns `Err` (no state yet), so the guard passes.
4. `state::set_state` writes `owner_id = "attacker.near"`.
5. All subsequent `require_owner_only` checks pass for `attacker.near`.
6. Attacker calls `upgrade` with malicious WASM to drain all bridged ETH and ERC-20 balances. [1](#0-0)

### Citations

**File:** engine/src/contract_methods/admin.rs (L56-88)
```rust
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

**File:** engine-workspace/src/lib.rs (L107-125)
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
```

**File:** engine/src/state.rs (L19-31)
```rust
pub struct EngineState {
    /// Chain id, according to the EIP-155 / ethereum-lists spec.
    pub chain_id: [u8; 32],
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
    /// Flag to pause and unpause the engine.
    pub is_paused: bool,
    /// Relayer key manager.
    pub key_manager: Option<AccountId>,
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
