### Title
Unprotected `new` Initialization Allows Any Caller to Seize Engine Ownership - (`engine/src/contract_methods/admin.rs`)

---

### Summary

The `new` function in `engine/src/contract_methods/admin.rs` is the one-time initialization entry point for the Aurora Engine. It sets the critical `EngineState` — including `owner_id`, `chain_id`, and `upgrade_delay_blocks` — but performs **no caller authentication**. Any unprivileged NEAR account that calls `new` before the legitimate deployer does will permanently seize ownership of the engine.

---

### Finding Description

The `new` function exposed at `engine/src/lib.rs` (line 77) as a public WASM export delegates to `contract_methods::admin::new`:

```rust
// engine/src/contract_methods/admin.rs, lines 55-88
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
```

The only guard is `state::get_state(&io).is_ok()` — a check that state does not yet exist. There is **no check on `env.predecessor_account_id()`** and no requirement that the caller be the contract account itself or any privileged party. Every other sensitive admin function (`set_owner`, `stage_upgrade`, `upgrade`, `pause_contract`) correctly calls `require_owner_only(&state, &env.predecessor_account_id())`, but `new` does not.

On NEAR Protocol, contract deployment and initialization are separate transactions unless the deployer explicitly uses a NEAR batch transaction. If the deployer sends a `DeployContract` transaction and then a separate `new` call, there is a window — observable via NEAR's transaction gossip — in which an attacker can submit their own `new` call with an attacker-controlled `owner_id` and win the race.

---

### Impact Explanation

Once the attacker's `new` call is accepted:

1. The attacker's account is stored as `owner_id` in `EngineState`.
2. All subsequent calls to `set_owner`, `stage_upgrade`, `upgrade`, `pause_contract`, `resume_contract`, `set_key_manager`, `add_relayer_key`, etc. gate on `require_owner_only`, which now passes only for the attacker.
3. The attacker can call `stage_upgrade` to store arbitrary WASM bytecode, then `deploy_upgrade` to replace the engine contract — enabling theft of all ETH and ERC-20 balances held by the engine.
4. Alternatively, the attacker can immediately call `pause_contract`, permanently freezing the engine and all user funds.

This satisfies **Critical: Direct theft of any user funds** and **Critical: Permanent freezing of funds**.

---

### Likelihood Explanation

- The attack requires only that the deployer does not use a NEAR batch transaction for deploy + init. This is a realistic deployment mistake and is not enforced by the contract itself.
- NEAR transactions are gossiped across the network before block inclusion, giving an attacker an observable window.
- The attacker needs no special privileges, tokens, or prior state — only the ability to submit a NEAR transaction.
- The contract provides zero on-chain protection against this; the entire security relies on an off-chain deployment convention.

---

### Recommendation

Add a caller check inside `new` that restricts initialization to the contract account itself (i.e., a self-call via a batch transaction), mirroring the pattern used by every other privileged function:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // Add: only the contract account itself may initialize
    if env.predecessor_account_id() != env.current_account_id() {
        return Err(b"ERR_NOT_ALLOWED".into());
    }
    ...
}
```

This forces the deployer to use a NEAR batch transaction (`DeployContract` + `FunctionCall("new", ...)`) where the predecessor is the contract account, making frontrunning impossible.

---

### Proof of Concept

1. Legitimate deployer sends a `DeployContract` transaction to deploy Aurora Engine to `aurora.near`.
2. Attacker observes this transaction in NEAR's transaction gossip pool.
3. Attacker immediately submits a call to `aurora.near::new` with `owner_id = attacker.near`, `chain_id = 1313161554`, `upgrade_delay_blocks = 0`.
4. Attacker's transaction is included before the deployer's `new` call (or races it).
5. Deployer's `new` call returns `ERR_ALREADY_INITIALIZED`.
6. Attacker calls `stage_upgrade` with malicious WASM bytecode (passes `require_owner_only` since attacker is now owner).
7. After `upgrade_delay_blocks` (set to 0 by attacker), attacker calls `deploy_upgrade`.
8. Malicious contract is live; all user ETH and ERC-20 balances are drained.

**Relevant code locations:**

- Unprotected `new` function: [1](#0-0) 
- Public WASM export with no access control: [2](#0-1) 
- `owner_id` field in `EngineState` that controls all privileged operations: [3](#0-2) 
- `stage_upgrade` gated on `require_owner_only` (attacker passes after seizing ownership): [4](#0-3) 
- `upgrade` gated on `require_owner_only`: [5](#0-4)

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

**File:** engine/src/contract_methods/admin.rs (L154-167)
```rust
pub fn stage_upgrade<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let delay_block_height = env.block_height() + state.upgrade_delay_blocks;
        require_owner_only(&state, &env.predecessor_account_id())?;
        io.read_input_and_store(&storage::bytes_to_key(KeyPrefix::Config, CODE_KEY));
        io.write_storage(
            &storage::bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY),
            &delay_block_height.to_le_bytes(),
        );
        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L169-200)
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
