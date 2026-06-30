### Title
Unpermissioned `deploy_upgrade` Allows Any Caller to Force Deployment of Staged Contract Code - (File: engine/src/lib.rs)

### Summary
The `deploy_upgrade` function in the Aurora Engine NEAR contract can be called by any NEAR account once the upgrade delay has elapsed. While `stage_upgrade` (which stores the code to be deployed) is correctly gated behind `require_owner_only`, `deploy_upgrade` performs no caller authentication at all. This asymmetry allows an attacker to force the deployment of staged code at the earliest possible moment, preventing the owner from cancelling a staged upgrade they have reconsidered.

### Finding Description
`stage_upgrade` stores new contract bytecode and records a future block height after which deployment is allowed. It is correctly restricted to the owner: [1](#0-0) 

`deploy_upgrade`, however, only checks that the contract is running and that the delay block has passed. There is no `require_owner_only` call: [2](#0-1) 

Compare this to every other state-mutating privileged function in the same file, all of which call `require_owner_only` or `require_owner_and_running`: [3](#0-2) 

The `require_owner_only` helper is available and used consistently everywhere else. Its absence from `deploy_upgrade` is the root cause.

### Impact Explanation
Once the upgrade delay elapses, any unprivileged NEAR account can call `deploy_upgrade` and atomically self-deploy the staged bytecode onto the Aurora Engine contract account. If the owner staged an upgrade and subsequently discovered a critical bug in the new code, their only recourse is to call `stage_upgrade` again with safe code (resetting the delay). An attacker monitoring the mempool can front-run that cancellation attempt by calling `deploy_upgrade` first, forcing the buggy code live. A buggy engine upgrade can corrupt EVM state, break accounting invariants, or introduce exploitable logic — any of which can result in permanent freezing of bridged ETH/NEP-141 funds or direct theft.

Impact: **Critical — permanent freezing of funds / insolvency** (from a forced deployment of a buggy upgrade the owner intended to cancel).

### Likelihood Explanation
The attacker's entry path is a direct, unauthenticated NEAR function call to `deploy_upgrade` with no arguments. The only precondition is that the owner has previously called `stage_upgrade` and the delay has elapsed. Because the Aurora Engine holds significant bridged value and upgrades are infrequent high-value events, a motivated attacker has strong incentive to monitor for staged upgrades and act at the first eligible block. Likelihood: **Medium** (requires a staged upgrade to be in flight, but the call itself is trivially executable by anyone).

### Recommendation
Add `require_owner_only` (or `require_owner_and_running`) to `deploy_upgrade`, mirroring the pattern used in `stage_upgrade` and every other privileged mutative function:

```rust
pub extern "C" fn deploy_upgrade() {
    let mut io = Runtime;
    let state = state::get_state(&io).sdk_unwrap();
    require_owner_and_running(&state, &io.predecessor_account_id())   // ADD THIS
        .map_err(ContractError::msg)
        .sdk_unwrap();
    let index = internal_get_upgrade_index();
    if io.block_height() <= index {
        sdk::panic_utf8(errors::ERR_NOT_ALLOWED_TOO_EARLY);
    }
    Runtime::self_deploy(&bytes_to_key(KeyPrefix::Config, CODE_KEY));
    io.remove_storage(&bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY));
}
```

Alternatively, introduce an explicit `cancel_upgrade` function so the owner can revoke a staged upgrade before an attacker can deploy it.

### Proof of Concept

1. Owner calls `stage_upgrade` with new bytecode `B`. This stores `B` at `CODE_KEY` and records `current_block + upgrade_delay_blocks` at `CODE_STAGE_KEY`.
2. Owner discovers a critical vulnerability in `B` and calls `stage_upgrade` again with safe bytecode `B'` to overwrite and reset the delay.
3. Attacker observes the pending cancellation transaction and submits `deploy_upgrade()` with higher gas priority in the same block.
4. `deploy_upgrade` succeeds: it reads `CODE_KEY` (still `B`), calls `Runtime::self_deploy`, and removes `CODE_STAGE_KEY`.
5. The Aurora Engine contract is now running buggy bytecode `B`. The owner's cancellation transaction fails because `CODE_STAGE_KEY` no longer exists.
6. The attacker (or anyone) can now exploit the bug in `B` to steal or freeze user funds. [2](#0-1) [1](#0-0)

### Citations

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

**File:** engine/src/lib.rs (L171-185)
```rust
    pub extern "C" fn deploy_upgrade() {
        // This function is intentionally not implemented in `contract_methods`
        // because it only makes sense in the context of the NEAR runtime.
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_running(&state)
            .map_err(ContractError::msg)
            .sdk_unwrap();
        let index = internal_get_upgrade_index();
        if io.block_height() <= index {
            sdk::panic_utf8(errors::ERR_NOT_ALLOWED_TOO_EARLY);
        }
        Runtime::self_deploy(&bytes_to_key(KeyPrefix::Config, CODE_KEY));
        io.remove_storage(&bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY));
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
