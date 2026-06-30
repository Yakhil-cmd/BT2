Looking at the Aurora Engine codebase, I need to find an analog to the "terminal state bypass via alternative state-changing functions" vulnerability class.

The key finding is in `start_hashchain` in `engine/src/contract_methods/admin.rs`: [1](#0-0) 

`start_hashchain` requires `require_paused` (line 428) and `require_key_manager_only` (line 429), then unconditionally sets `state.is_paused = false` at line 460.

Meanwhile, `resume_contract` enforces `require_owner_only`: [2](#0-1) 

And `pause_contract` is also owner-only: [3](#0-2) 

The key manager is a distinct role from the owner, set via `set_key_manager` which requires `require_owner_only`: [4](#0-3) 

The `EngineState` uses a single `is_paused` boolean with no distinction between a security pause and a hashchain-initialization pause: [5](#0-4) 

---

### Title
`start_hashchain` Bypasses Owner-Controlled Security Pause via Key Manager Role — (File: `engine/src/contract_methods/admin.rs`)

### Summary
The `start_hashchain` function unconditionally clears `state.is_paused` after initializing the hashchain, giving the key manager an alternative pathway to resume a contract that the owner paused for security reasons. This bypasses the owner-only restriction that `resume_contract` enforces.

### Finding Description
Aurora Engine exposes two ways to resume a paused contract:

1. **`resume_contract`** — enforces `require_owner_only` + `require_paused`. Only the owner can call it.
2. **`start_hashchain`** — enforces `require_paused` + `require_key_manager_only`, then unconditionally executes `state.is_paused = false` (line 460) before saving state.

The key manager is a separate privileged role from the owner. It is set by the owner via `set_key_manager` and is intended to manage relayer function-call keys (`add_relayer_key`, `remove_relayer_key`). The `start_hashchain` function is designed to initialize the hashchain integrity system while the contract is paused, and it resumes the contract as a side effect of that initialization.

Because the single `is_paused` flag is shared between a security pause and a hashchain-initialization pause, the key manager can call `start_hashchain` at any time the contract is paused — including when the owner paused it as an emergency security measure — and the contract will be unconditionally resumed.

The state machine is:

```
Owner calls pause_contract  →  is_paused = true
Key manager calls start_hashchain  →  is_paused = false  (bypass)
```

whereas the intended exclusive resume path is:

```
Owner calls resume_contract  →  is_paused = false  (authorized)
``` [6](#0-5) 

### Impact Explanation
If the owner pauses the contract in response to an active exploit draining user funds, the key manager can inadvertently (or intentionally) resume the contract by calling `start_hashchain`. Once resumed, the exploit can continue, leading to **direct theft of user funds** (Critical). The `pause_contract` security guarantee — that only the owner can resume — is silently violated.

### Likelihood Explanation
The key manager is a separate operational entity (e.g., a relayer operator) that may not be informed of an emergency security pause. In a real deployment, the key manager might legitimately attempt to initialize the hashchain while the contract is paused, not realizing this will also resume the contract and undo the owner's security measure. No malicious intent is required; the design flaw alone is sufficient.

### Recommendation
1. Introduce a separate flag (e.g., `is_security_paused: bool`) to distinguish a security pause from a hashchain-initialization pause, and have `start_hashchain` check that the pause is not a security pause before clearing `is_paused`.
2. Alternatively, require `require_owner_only` (in addition to `require_key_manager_only`) inside `start_hashchain`, so that resuming the contract always requires the owner's authorization.
3. Or, decouple the hashchain initialization from the contract-resume side effect: let `start_hashchain` only initialize the hashchain data without touching `is_paused`, and require a separate explicit `resume_contract` call by the owner afterward.

### Proof of Concept
```
1. Owner calls `pause_contract`  →  state.is_paused = true
   (Reason: active exploit detected, all EVM transactions must stop)

2. Key manager calls `start_hashchain` with valid StartHashchainArgs
   →  require_paused passes  (contract is paused ✓)
   →  require_key_manager_only passes  (key manager is set ✓)
   →  hashchain is initialized
   →  state.is_paused = false  ← unconditional, line 460

3. Contract is now running again.
   `submit`, `call`, `deploy_code` all pass `require_running`.
   The exploit that triggered the pause can continue executing.
``` [7](#0-6)

### Citations

**File:** engine/src/contract_methods/admin.rs (L250-260)
```rust
#[named]
pub fn pause_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_running(&state)?;
        state.is_paused = true;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L262-272)
```rust
#[named]
pub fn resume_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_paused(&state)?;
        state.is_paused = false;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L274-296)
```rust
#[named]
pub fn set_key_manager<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;

        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;

        let key_manager =
            serde_json::from_slice::<RelayerKeyManagerArgs>(&io.read_input().to_vec())
                .map(|args| args.key_manager)
                .map_err(|_| errors::ERR_JSON_DESERIALIZE)?;

        if state.key_manager == key_manager {
            return Err(errors::ERR_SAME_KEY_MANAGER.into());
        }

        state.key_manager = key_manager;
        state::set_state(&mut io, &state)?;

        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L425-464)
```rust
#[named]
pub fn start_hashchain<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    let mut state = state::get_state(&io)?;
    require_paused(&state)?;
    require_key_manager_only(&state, &env.predecessor_account_id())?;

    let input = io.read_input().to_vec();
    let args = StartHashchainArgs::try_from_slice(&input).map_err(|_| errors::ERR_SERIALIZE)?;
    let block_height = env.block_height();

    // Starting hashchain must be for an earlier block
    if block_height < args.block_height {
        return Err(errors::ERR_ARGS.into());
    }

    let mut hashchain = Hashchain::new(
        state.chain_id,
        env.current_account_id(),
        args.block_height + 1,
        args.block_hashchain,
    );

    if hashchain.get_current_block_height() < block_height {
        hashchain.move_to_block(block_height)?;
    }

    hashchain.add_block_tx(
        block_height,
        function_name!(),
        &input,
        &[],
        &Bloom::default(),
    )?;
    crate::hashchain::save_hashchain(&mut io, &hashchain)?;

    state.is_paused = false;
    state::set_state(&mut io, &state)?;

    Ok(())
}
```

**File:** engine/src/state.rs (L18-31)
```rust
#[derive(Default, Clone, PartialEq, Eq, Debug)]
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
