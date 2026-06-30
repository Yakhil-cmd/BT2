### Title
Single-Step Ownership Transfer Permanently Locks Engine Admin Control - (File: engine/src/contract_methods/admin.rs)

### Summary
The Aurora Engine's `set_owner` function immediately and irrevocably replaces `state.owner_id` in a single atomic step. There is no pending-owner confirmation mechanism. A typo or wrong NEAR account ID supplied by the current owner permanently transfers control to an uncontrollable address, eliminating the only account authorized to pause the contract, deploy upgrades, attach full-access keys, and manage relayer keys — all of which are the sole recovery mechanisms for any future critical bug affecting bridged user funds.

---

### Finding Description

`set_owner` in `engine/src/contract_methods/admin.rs` reads the caller-supplied `SetOwnerArgs`, validates only that the new owner differs from the current one, then immediately overwrites `state.owner_id` and persists it:

```rust
// engine/src/contract_methods/admin.rs, lines 103-121
pub fn set_owner<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;

        let args: SetOwnerArgs = io.read_input_borsh()?;
        if state.owner_id == args.new_owner {
            return Err(errors::ERR_SAME_OWNER.into());
        }

        state.owner_id = args.new_owner;   // ← immediate, unconditional overwrite
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
``` [1](#0-0) 

The new address is never required to prove it controls the target account. The only guard is `ERR_SAME_OWNER`, which does not protect against a wrong-but-different address. [2](#0-1) 

`owner_id` is the sole account authorized for every critical administrative action:

| Function | Guard |
|---|---|
| `upgrade` / `stage_upgrade` | `require_owner_only` |
| `pause_contract` / `resume_contract` | `require_owner_only` |
| `attach_full_access_key` | `require_owner_only` |
| `set_key_manager` | `require_owner_only` |
| `factory_set_wnear_address` | `require_owner_only` | [3](#0-2) [4](#0-3) [5](#0-4) 

`EngineState.owner_id` is the single field gating all of these: [6](#0-5) 

There is no secondary privileged account, no time-lock recovery path, and no on-chain mechanism to reclaim ownership once it is transferred to an uncontrolled address.

---

### Impact Explanation

**Permanent freezing of funds — High.**

Aurora Engine is a live bridge holding user-deposited ETH and ERC-20 tokens. The `upgrade` and `pause_contract` functions are the only on-chain mechanisms to respond to a critical bug or active exploit. If `owner_id` is set to an uncontrolled address:

1. `pause_contract` can never be called → an active exploit draining the bridge cannot be halted.
2. `upgrade` / `stage_upgrade` can never be called → no patched contract code can be deployed.
3. `attach_full_access_key` can never be called → no out-of-band NEAR-level recovery is possible.

All bridged user funds become permanently unrecoverable in the presence of any subsequent bug, satisfying the "permanent freezing of funds" criterion.

---

### Likelihood Explanation

**Medium.** NEAR account IDs are arbitrary UTF-8 strings (e.g., `aurora`, `dao.aurora.near`, `multisig.aurora.near`). A single-character typo produces a syntactically valid but unowned account ID. The `SetOwnerArgs` struct accepts any `AccountId` that passes NEAR's format check: [7](#0-6) 

No existence check is performed on the supplied account before the state is committed. Ownership transfers are infrequent but high-stakes operations, making a fat-finger mistake realistic.

---

### Recommendation

Implement a two-step ownership transfer:

1. **Propose**: the current owner calls `set_owner(new_owner)`, which stores `pending_owner_id` in `EngineState` without changing `owner_id`.
2. **Accept**: the proposed new owner calls a new `accept_ownership()` function, which moves `pending_owner_id` into `owner_id` only after the new owner has proven control by signing the accepting transaction.

Add `pending_owner: Option<AccountId>` to `EngineState` and a corresponding `accept_ownership` entry point in `admin.rs` and `lib.rs`.

---

### Proof of Concept

1. Current owner (`aurora.near`) calls `set_owner` with `SetOwnerArgs { new_owner: "auroa.near" }` (one-character typo).
2. `set_owner` passes the `ERR_SAME_OWNER` check (different string), overwrites `state.owner_id = "auroa.near"`, and calls `state::set_state`. [8](#0-7) 

3. `"auroa.near"` does not exist or is not controlled by the operator.
4. All subsequent calls to `upgrade`, `pause_contract`, `attach_full_access_key`, and `set_key_manager` fail with `ERR_NOT_ALLOWED` because `require_owner_only` compares `state.owner_id` (`"auroa.near"`) against `predecessor_account_id` (`"aurora.near"`). [9](#0-8) 

5. The engine is now permanently unupgradeable and unpauseable. Any future critical vulnerability in the bridge or EVM execution layer cannot be mitigated on-chain, resulting in permanent freezing (or unrecoverable theft) of all bridged user funds.

### Citations

**File:** engine/src/contract_methods/admin.rs (L103-121)
```rust
#[named]
pub fn set_owner<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;

        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;

        let args: SetOwnerArgs = io.read_input_borsh()?;
        if state.owner_id == args.new_owner {
            return Err(errors::ERR_SAME_OWNER.into());
        }

        state.owner_id = args.new_owner;
        state::set_state(&mut io, &state)?;

        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L154-176)
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

pub fn upgrade<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;
```

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

**File:** engine-types/src/parameters/engine.rs (L117-122)
```rust
/// Borsh-encoded parameters for the `set_owner` function.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "impl-serde", derive(Serialize, Deserialize))]
pub struct SetOwnerArgs {
    pub new_owner: AccountId,
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
