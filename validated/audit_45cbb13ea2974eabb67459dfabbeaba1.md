### Title
Missing Minimum Value Check in `set_upgrade_delay_blocks` Collapses Upgrade Timelock Protection - (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

The `set_upgrade_delay_blocks` function accepts any `u64` value — including `0` — for `upgrade_delay_blocks` with no minimum validation. This field is the sole timelock controlling how many blocks must pass between staging and deploying a contract upgrade. Setting it to `0` allows the owner to stage and deploy a malicious WASM upgrade atomically in the same block, giving users zero time to detect and exit before a fund-draining upgrade takes effect.

---

### Finding Description

`EngineState.upgrade_delay_blocks` is documented as "How many blocks after staging upgrade can deploy it." [1](#0-0) 

The setter function performs no minimum-value guard:

```rust
pub fn set_upgrade_delay_blocks<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        let args: SetUpgradeDelayBlocksArgs = io.read_input_borsh()?;
        state.upgrade_delay_blocks = args.upgrade_delay_blocks;   // ← no minimum check
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
``` [2](#0-1) 

`stage_upgrade` then computes the earliest deploy block as:

```rust
let delay_block_height = env.block_height() + state.upgrade_delay_blocks;
``` [3](#0-2) 

When `upgrade_delay_blocks = 0`, `delay_block_height == env.block_height()`, so the staged upgrade is immediately eligible for deployment in the same block it was staged. The `upgrade` function then deploys the new WASM contract via a NEAR promise batch with no independent delay check of its own: [4](#0-3) 

The public NEAR entrypoint `set_upgrade_delay_blocks` is exposed without restriction beyond `require_owner_only`: [5](#0-4) 

---

### Impact Explanation

**Critical — Direct theft of all user funds / permanent fund freeze.**

The Aurora Engine contract holds all EVM-side ETH balances and ERC-20 mirror token state. A WASM upgrade replaces the entire contract logic. If `upgrade_delay_blocks` is `0`, the owner can:

1. Call `set_upgrade_delay_blocks(0)` — accepted with no guard.
2. Call `stage_upgrade` with a malicious WASM blob in the same or next block.
3. Immediately call `upgrade` (or the staged-deploy path) in the same block.

The malicious contract can drain all ETH balances, corrupt ERC-20 mirror accounting, or brick the contract permanently. Users have no observable window to withdraw funds before the upgrade is live.

---

### Likelihood Explanation

**Low-to-Medium.** The owner account on Aurora mainnet is a DAO/multisig, so accidental or unilateral misuse requires governance capture or key compromise. However, the absence of any on-chain guard means a single erroneous governance proposal or a compromised key can silently zero out the delay. The external report's acknowledged scenario — an owner accidentally setting the value to `0` — applies identically here. Unlike the Connext case, Aurora's `upgrade_delay_blocks` is the *only* on-chain protection between staging and deploying a full contract replacement, making the consequence of a zero value more severe.

---

### Recommendation

Introduce a compile-time or storage-backed `MIN_UPGRADE_DELAY_BLOCKS` constant and enforce it in `set_upgrade_delay_blocks`:

```rust
const MIN_UPGRADE_DELAY_BLOCKS: u64 = 1000; // ~12 hours on NEAR (~1.3 s/block)

pub fn set_upgrade_delay_blocks<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        let args: SetUpgradeDelayBlocksArgs = io.read_input_borsh()?;
        if args.upgrade_delay_blocks < MIN_UPGRADE_DELAY_BLOCKS {
            return Err(b"ERR_DELAY_TOO_SHORT".into());
        }
        state.upgrade_delay_blocks = args.upgrade_delay_blocks;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

If the minimum itself must be configurable, changing it should require its own timelock (analogous to the 72-hour suggestion in the external report).

---

### Proof of Concept

```
Block N:
  owner → set_upgrade_delay_blocks(upgrade_delay_blocks: 0)
  // Accepted. No minimum check. State updated.

Block N+1:
  owner → stage_upgrade(malicious_wasm_bytes)
  // delay_block_height = (N+1) + 0 = N+1
  // Staged code stored. Eligible for deploy immediately.

Block N+1 (same block, next action):
  owner → upgrade(malicious_wasm_bytes)
  // Deploys malicious WASM. All user ETH balances and ERC-20 state
  // are now under attacker control. Funds drained.
```

Root cause: [6](#0-5) 
Timelock computation: [7](#0-6) 
Parameter type (accepts 0): [8](#0-7)

### Citations

**File:** engine/src/state.rs (L25-26)
```rust
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
```

**File:** engine/src/contract_methods/admin.rs (L134-145)
```rust
#[named]
pub fn set_upgrade_delay_blocks<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        let args: SetUpgradeDelayBlocksArgs = io.read_input_borsh()?;
        state.upgrade_delay_blocks = args.upgrade_delay_blocks;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L158-163)
```rust
        let delay_block_height = env.block_height() + state.upgrade_delay_blocks;
        require_owner_only(&state, &env.predecessor_account_id())?;
        io.read_input_and_store(&storage::bytes_to_key(KeyPrefix::Config, CODE_KEY));
        io.write_storage(
            &storage::bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY),
            &delay_block_height.to_le_bytes(),
```

**File:** engine/src/contract_methods/admin.rs (L169-205)
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
```

**File:** engine/src/lib.rs (L130-137)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn set_upgrade_delay_blocks() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::set_upgrade_delay_blocks(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine-types/src/parameters/engine.rs (L127-129)
```rust
pub struct SetUpgradeDelayBlocksArgs {
    pub upgrade_delay_blocks: u64,
}
```
