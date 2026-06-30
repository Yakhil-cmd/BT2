Looking at the `upgrade` and `stage_upgrade` functions in `engine/src/contract_methods/admin.rs`, and the `EngineState.upgrade_delay_blocks` field in `engine/src/state.rs`, I can confirm a direct analog.

---

### Title
Owner Can Immediately Execute Contract Upgrades, Bypassing the `upgrade_delay_blocks` Time-Lock - (File: `engine/src/contract_methods/admin.rs`)

### Summary
The `upgrade` function in `engine/src/contract_methods/admin.rs` never reads or enforces the delay block height stored by `stage_upgrade`. The `upgrade_delay_blocks` field in `EngineState` and the `CODE_STAGE_KEY` storage slot are entirely ignored during upgrade execution, allowing the owner to deploy arbitrary new contract code immediately — without any notice period — over all user funds held in the Aurora Engine.

### Finding Description

The Aurora Engine implements a two-step upgrade mechanism:

**Step 1 — `stage_upgrade`** (lines 153–167) computes a future block height at which the upgrade may execute and stores it:

```rust
let delay_block_height = env.block_height() + state.upgrade_delay_blocks;
// ...
io.write_storage(
    &storage::bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY),
    &delay_block_height.to_le_bytes(),
);
``` [1](#0-0) 

**Step 2 — `upgrade`** (lines 169–206) is supposed to enforce that the delay has passed before deploying new code. Instead, it only checks `require_running` and `require_owner_only`, then immediately deploys whatever code is passed as input:

```rust
pub fn upgrade<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I, env: &E, handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;

    let input = io.read_input().to_vec();
    // ... deploys `input` directly — no check of CODE_STAGE_KEY
``` [2](#0-1) 

The `CODE_STAGE_KEY` value (the earliest permitted upgrade block) is **never read inside `upgrade`**. The only place it is read is in the view-only helper `internal_get_upgrade_index`, which feeds `get_upgrade_index` — a read function with no enforcement role. [3](#0-2) 

Furthermore, `upgrade` reads code from `io.read_input()` — fresh calldata — rather than from the `CODE_KEY` slot where `stage_upgrade` stored the pre-committed code. This means `stage_upgrade` need not be called at all; the owner can skip directly to `upgrade` with any payload.

The `upgrade_delay_blocks` field in `EngineState` is stored and settable, but its value is never enforced at upgrade time: [4](#0-3) 

### Impact Explanation

**Critical — Direct theft of all user funds.**

The Aurora Engine contract holds all bridged ETH and ERC-20 token balances for every Aurora user. A malicious or compromised owner can call `upgrade` in a single transaction, deploying arbitrary WASM code that re-routes withdrawals, mints tokens, or drains the contract's entire balance — with zero advance notice to users. The upgrade delay is the only mechanism that gives users time to exit before a hostile upgrade takes effect. Because the delay is never enforced, that protection is entirely absent.

### Likelihood Explanation

The upgrade delay mechanism is explicitly designed to constrain the owner's unilateral power. The `upgrade_delay_blocks` field is configurable and documented as "How many blocks after staging upgrade can deploy it" (`state.rs` line 25–26). The existence of `stage_upgrade` and `get_upgrade_index` confirms the intent. The bug is that the enforcement step was simply never written into `upgrade`. Any owner — whether rogue, key-compromised, or socially engineered — can exploit this silently, in one transaction, with no on-chain warning.

### Recommendation

Inside `upgrade`, before deploying code:
1. Read the stored delay block height from `CODE_STAGE_KEY`.
2. Assert `env.block_height() >= stored_delay_block_height` (and that the key exists, i.e., `stage_upgrade` was called).
3. Deploy the code from `CODE_KEY` (the pre-committed staged code) rather than from fresh `read_input()`, so the code that executes is the same code users observed during the notice period.

### Proof of Concept

```
// Owner calls stage_upgrade at block N with code A.
// CODE_STAGE_KEY is set to N + upgrade_delay_blocks.
// CODE_KEY is set to code A.

// Immediately (same block or next block), owner calls upgrade()
// with code B (malicious drain payload) as input.
// upgrade() checks only require_running + require_owner_only.
// It reads code B from io.read_input() — ignoring CODE_KEY and CODE_STAGE_KEY.
// PromiseBatchAction::DeployContract { code: B } executes immediately.
// All user funds are now under control of code B.
```

The owner can also skip `stage_upgrade` entirely and call `upgrade` directly — the function has no dependency on the staging step. [2](#0-1) [5](#0-4)

### Citations

**File:** engine/src/contract_methods/admin.rs (L147-151)
```rust
pub fn get_upgrade_index<I: IO + Copy>(mut io: I) -> Result<(), ContractError> {
    let index = internal_get_upgrade_index(&io)?;
    io.return_output(&index.to_le_bytes());
    Ok(())
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

**File:** engine/src/state.rs (L25-27)
```rust
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
    /// Flag to pause and unpause the engine.
```
