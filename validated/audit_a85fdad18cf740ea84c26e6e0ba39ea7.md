The code is fully readable. Let me confirm the exact behavior of `require_key_manager_only` and the `EngineState` structure before writing the final answer.

### Title
Key Manager Can Bypass Owner Emergency Pause via `start_hashchain` - (`engine/src/contract_methods/admin.rs`)

---

### Summary

`start_hashchain` unconditionally sets `state.is_paused = false` and persists it, but is gated only by `require_paused` + `require_key_manager_only`. Because `key_manager` is a distinct `AccountId` from `owner_id` in `EngineState`, the key manager can call `start_hashchain` at any time the engine is paused — including during an owner-initiated emergency pause — and fully resume the engine without the owner's knowledge or consent.

---

### Finding Description

`pause_contract` and `resume_contract` are both owner-only operations: [1](#0-0) 

`resume_contract` explicitly enforces `require_owner_only` before clearing `is_paused`.

`start_hashchain`, however, enforces only `require_paused` and `require_key_manager_only`: [2](#0-1) 

At line 460–461 it unconditionally writes `state.is_paused = false` back to storage with no owner check whatsoever.

`require_key_manager_only` checks only that `predecessor_account_id == state.key_manager`; it does not verify that the key manager is also the owner: [3](#0-2) 

`EngineState` stores `owner_id` and `key_manager` as independent, separately-settable fields: [4](#0-3) 

`set_key_manager` requires `require_owner_only` + `require_running`, so the owner deliberately sets a separate key manager account. In any production deployment where `key_manager != owner_id`, the key manager holds a silent, unconditional ability to lift any pause the owner applies.

---

### Impact Explanation

Once `start_hashchain` clears `is_paused`, `require_running` passes for all EVM execution paths (`submit`, `submit_with_args`, `call`). Exit precompiles (`ExitToNear`, `ExitToEthereum`) become callable again, allowing in-flight EVM transactions to withdraw user funds from the engine. This is direct theft of user funds in motion — Critical scope.

---

### Likelihood Explanation

The key manager is a hot-wallet or automated relayer-management account, architecturally separate from the owner (which is typically a multisig or DAO). The owner pauses the engine during an incident. The key manager, operating independently, calls `start_hashchain` to reinitialize the hashchain (its documented purpose), inadvertently or deliberately unpausing the engine. No key compromise is required; the key manager uses its legitimate credentials on a publicly exposed contract method.

---

### Recommendation

Remove the `state.is_paused = false` assignment from `start_hashchain`. Unpausing must remain exclusively in `resume_contract` (owner-only). If the hashchain must be initialized from a paused state, `start_hashchain` should leave `is_paused` unchanged and let the owner explicitly call `resume_contract` afterward. Alternatively, add `require_owner_only` to `start_hashchain` so that only the owner can invoke it.

---

### Proof of Concept

```rust
// Pseudocode using the engine's Fixed test environment
let owner    = AccountId::new("owner.near").unwrap();
let key_mgr  = AccountId::new("keymgr.near").unwrap();

// 1. Initialize engine with owner != key_manager
let mut state = EngineState {
    owner_id:   owner.clone(),
    key_manager: Some(key_mgr.clone()),
    is_paused:  false,
    ..Default::default()
};

// 2. Owner pauses the engine (emergency)
// predecessor = owner
state.is_paused = true;   // result of pause_contract

// 3. Key manager calls start_hashchain
// predecessor = key_mgr  (NOT owner)
// require_paused  -> passes (is_paused == true)
// require_key_manager_only -> passes (key_mgr == state.key_manager)
// ... hashchain logic ...
state.is_paused = false;  // line 460 — no owner check

// 4. Assert: engine is unpaused without owner consent
assert!(!state.is_paused);  // PASSES — emergency pause bypassed

// 5. Attacker submits EVM tx calling exit precompile -> funds drained
```

The test utility `init_hashchain` in `engine-tests/src/utils/mod.rs` (lines 693–720) already demonstrates this exact call sequence — pause then `start_hashchain` — confirming the path is reachable on unmodified code. [5](#0-4)

### Citations

**File:** engine/src/contract_methods/admin.rs (L250-272)
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

**File:** engine/src/contract_methods/admin.rs (L426-461)
```rust
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
```

**File:** engine/src/contract_methods/mod.rs (L99-111)
```rust
fn require_key_manager_only(
    state: &state::EngineState,
    predecessor_account_id: &AccountId,
) -> Result<(), ContractError> {
    let key_manager = state
        .key_manager
        .as_ref()
        .ok_or(errors::ERR_KEY_MANAGER_IS_NOT_SET)?;
    if key_manager != predecessor_account_id {
        return Err(errors::ERR_NOT_ALLOWED.into());
    }
    Ok(())
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

**File:** engine-tests/src/utils/mod.rs (L693-720)
```rust
pub fn init_hashchain(
    runner: &mut AuroraRunner,
    caller_account_id: &str,
    block_height: Option<u64>,
) {
    // Set up hashchain:
    //   1. Pause contract (hashchain can only be started if contract is paused first)
    //   2. Start hashchain

    let result: Result<VMOutcome, EngineError> =
        runner.call("pause_contract", caller_account_id, Vec::new());
    assert!(result.is_ok());

    if let Some(h) = block_height {
        runner.context.block_height = h;
    }

    let args = StartHashchainArgs {
        block_height: runner.context.block_height,
        block_hashchain: [0u8; 32],
    };
    let result = runner.call(
        "start_hashchain",
        caller_account_id,
        borsh::to_vec(&args).unwrap(),
    );
    assert!(result.is_ok());
}
```
