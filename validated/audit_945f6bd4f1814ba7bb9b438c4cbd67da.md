### Title
Owner Can Immediately Deploy Arbitrary Contract Code With No Delay, Enabling Total Fund Theft - (File: `engine/src/contract_methods/admin.rs`)

### Summary

The Aurora Engine exposes two upgrade paths. The `stage_upgrade` / `deploy_upgrade` path is gated by `upgrade_delay_blocks`, but a second path — `upgrade()` — deploys new WASM code **immediately** with zero delay. Additionally, `set_upgrade_delay_blocks` enforces no minimum value, so the owner can atomically reduce the delay to `0` and then use the staged path with the same effect. Either path lets the owner silently replace the entire contract with malicious code before any user can react, enabling total theft of all bridged ETH and ERC-20 balances held in the engine.

---

### Finding Description

**Path 1 — `upgrade()`: zero-delay immediate code replacement**

`upgrade()` in `engine/src/contract_methods/admin.rs` requires only `require_owner_only` and `require_running`, then immediately schedules a `DeployContract` promise on the engine's own account:

```
require_running(&state)?;
require_owner_only(&state, &env.predecessor_account_id())?;
// ... builds PromiseBatchAction with DeployContract { code } ...
handler.promise_return(promise_id);
```

There is no `upgrade_delay_blocks` check, no staging step, and no minimum waiting period. The new WASM is live in the same NEAR receipt batch. [1](#0-0) 

**Path 2 — `set_upgrade_delay_blocks()` to 0, then `stage_upgrade` + `deploy_upgrade`**

`set_upgrade_delay_blocks` writes the caller-supplied value directly into state with no lower-bound check:

```rust
let args: SetUpgradeDelayBlocksArgs = io.read_input_borsh()?;
state.upgrade_delay_blocks = args.upgrade_delay_blocks;
state::set_state(&mut io, &state)?;
``` [2](#0-1) 

`stage_upgrade` computes the deploy-eligible block as `env.block_height() + state.upgrade_delay_blocks`. With `upgrade_delay_blocks = 0` this equals the current block height, and `deploy_upgrade` checks `if io.block_height() <= index` (strict `<=`), so the staged code becomes deployable in the very next block — effectively zero delay. [3](#0-2) [4](#0-3) 

`SetUpgradeDelayBlocksArgs` carries a bare `u64` with no protocol-level minimum: [5](#0-4) 

---

### Impact Explanation

The Aurora Engine holds all bridged ETH and ERC-20 token balances for every user on the Aurora EVM. A malicious WASM replacement can rewrite any storage slot, redirect `ft_transfer` / `withdraw` logic, or simply drain the engine's NEAR balance. This constitutes **direct theft of all user funds at rest** — the highest-severity impact class.

---

### Likelihood Explanation

The `upgrade()` entry point is a single NEAR transaction callable by whoever holds the `owner_id` key. No multi-step process, no on-chain announcement, and no minimum delay stands between the owner and a full contract replacement. Any compromise of the owner key (or a malicious owner) can execute this in one block with no observable warning to users.

---

### Recommendation

1. **Remove or gate the immediate `upgrade()` path.** Either delete it entirely or require it to go through the same staged delay as `stage_upgrade` / `deploy_upgrade`.
2. **Enforce a minimum `upgrade_delay_blocks` value** in `set_upgrade_delay_blocks` (e.g., a constant representing ≥ 48 hours of NEAR block time, roughly `172 800` blocks at ~1 s/block). Reject any call that attempts to set a value below this floor.
3. **Apply the same minimum at initialization** in `new()` so the delay cannot be set to an unsafe value at deployment time.

---

### Proof of Concept

```
// Step 1: Owner calls upgrade() with malicious WASM — no delay, no staging.
aurora.upgrade(malicious_wasm_bytes)   // single NEAR tx, immediate effect

// OR

// Step 1a: Owner sets delay to 0
aurora.set_upgrade_delay_blocks({ upgrade_delay_blocks: 0 })

// Step 1b: Owner stages malicious code (deploy-eligible block = current block)
aurora.stage_upgrade(malicious_wasm_bytes)

// Step 1c: Anyone calls deploy_upgrade in the next block
aurora.deploy_upgrade()   // block_height > index (0 + current_block), passes check

// Result: Malicious contract is live. All bridged ETH and ERC-20 balances
// can be redirected or drained by the attacker-controlled replacement code.
```

### Citations

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

**File:** engine/src/contract_methods/admin.rs (L153-167)
```rust
#[named]
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

**File:** engine/src/lib.rs (L179-184)
```rust
        let index = internal_get_upgrade_index();
        if io.block_height() <= index {
            sdk::panic_utf8(errors::ERR_NOT_ALLOWED_TOO_EARLY);
        }
        Runtime::self_deploy(&bytes_to_key(KeyPrefix::Config, CODE_KEY));
        io.remove_storage(&bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY));
```

**File:** engine-types/src/parameters/engine.rs (L124-129)
```rust
/// Borsh-encoded parameters for the `set_upgrade_delay_blocks` function.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "impl-serde", derive(Serialize, Deserialize))]
pub struct SetUpgradeDelayBlocksArgs {
    pub upgrade_delay_blocks: u64,
}
```
