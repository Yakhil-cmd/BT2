### Title
Missing Validation of `owner_id`/`new_owner` in `new()` and `set_owner()` Could Permanently Lock Owner Role - (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

The `new()` initializer and `set_owner()` function in the Aurora Engine accept an arbitrary `owner_id` / `new_owner` NEAR `AccountId` with no validation that the account actually exists on-chain. If an incorrect or non-existent account ID is supplied — either at deployment or during an ownership transfer — the owner role is permanently and irrecoverably locked. Every owner-gated operation (pause, upgrade, key-manager management, wNEAR configuration) becomes permanently inaccessible with no recovery path short of a full redeploy.

---

### Finding Description

**`new()` — initialization path**

`engine/src/contract_methods/admin.rs` lines 56–88 deserialize `NewCallArgs` and store the embedded `owner_id` directly into `EngineState` with no existence check:

```rust
let args = NewCallArgs::deserialize(&input)...;
let state: EngineState = args.into();   // owner_id stored verbatim
state::set_state(&mut io, &state)?;
```

`EngineState.owner_id` is typed as `AccountId`, which enforces only NEAR account-ID *format* rules (lowercase, valid characters), not on-chain *existence*. A syntactically valid but non-existent account (e.g. `"typo.near"`) passes deserialization and is committed to state.

**`set_owner()` — post-deployment path**

Lines 104–121 of the same file accept any `new_owner` from the current owner and write it unconditionally:

```rust
let args: SetOwnerArgs = io.read_input_borsh()?;
if state.owner_id == args.new_owner {
    return Err(errors::ERR_SAME_OWNER.into());
}
state.owner_id = args.new_owner;   // no existence check, no two-step confirmation
state::set_state(&mut io, &state)?;
```

There is no two-step confirmation (propose → accept), no check that the new account exists, and no `renounce_ownership` escape hatch. Once the wrong account ID is committed, `require_owner_only` will never pass again because no real key-holder controls that account.

**Owner-gated functions that become permanently inaccessible:**

| Function | Consequence if locked |
|---|---|
| `pause_contract` / `resume_contract` | Contract can never be paused in a security incident |
| `stage_upgrade` / `deploy_upgrade` | Critical security patches can never be applied |
| `set_key_manager` | Relayer key management permanently broken |
| `factory_set_wnear_address` | XCC wNEAR routing permanently frozen |
| `set_erc20_metadata` | ERC-20 mirror metadata permanently frozen |
| `set_owner` itself | Ownership can never be corrected |

---

### Impact Explanation

**Classification: Critical — Permanent Freezing of Funds**

If the owner role is permanently locked:

1. `pause_contract` is inaccessible. If any exploit is discovered in the EVM execution path, bridge accounting, or precompile logic, the engine cannot be halted. Attackers can drain funds without interruption.
2. `stage_upgrade` / `deploy_upgrade` are inaccessible. No security patch can ever be applied. Any discovered vulnerability becomes permanently exploitable, leading to permanent fund loss for all users whose assets are held in the Aurora EVM state or the ETH connector.
3. The XCC wNEAR address and relayer key infrastructure cannot be updated, permanently degrading cross-chain functionality.

The inability to pause or upgrade a live contract holding user funds is equivalent to a permanent fund-freeze vector: once a critical bug is found, there is no circuit-breaker.

---

### Likelihood Explanation

**Likelihood: Low-Medium**

Two realistic trigger paths exist:

1. **Deployment mistake**: The deployer calls `new()` with a typo in `owner_id` (e.g., `"auroa"` instead of `"aurora"`). NEAR `AccountId` format validation accepts this; the engine initializes successfully and appears functional. The mistake may not be noticed until an owner-only operation is attempted.

2. **Ownership transfer mistake**: The current owner calls `set_owner()` with a mistyped or stale account ID. The transaction succeeds immediately with no confirmation step. There is no undo.

Both paths require only a single honest mistake by the deployer or owner — no adversarial action is needed. The original UniswapV3 audit identified the identical pattern as high-severity precisely because the contract continues to function normally (users can transact) while the administrative role is silently bricked.

---

### Recommendation

1. **Two-step ownership transfer**: Introduce a `propose_owner` / `accept_owner` pattern. The new owner must call `accept_owner()` from their own account before the transfer is finalized. This proves the new account is live and controlled.

2. **Designate `predecessor_account_id` as the initial owner** in `new()`, then transfer ownership post-deployment. This eliminates the constructor misconfiguration vector.

3. **Add a `renounce_ownership` function** if intentional owner removal is ever needed, rather than relying on setting an invalid address.

4. **Integrate Slither or equivalent static analysis** into CI to catch missing zero/existence checks on privileged role assignments.

---

### Proof of Concept

**Scenario A — Deployment misconfiguration:**

1. Deployer calls `new()` with `NewCallArgs` containing `owner_id = "auroa.near"` (typo; account does not exist).
2. `NewCallArgs::deserialize` succeeds — `"auroa.near"` is a valid NEAR account ID format.
3. `EngineState { owner_id: "auroa.near", ... }` is written to storage.
4. The engine initializes normally; EVM transactions, bridging, and all user-facing operations work.
5. A critical vulnerability is later discovered. The security team calls `pause_contract` from `"aurora.near"`.
6. `require_owner_only` compares `"aurora.near" != "auroa.near"` → `ERR_NOT_ALLOWED`. The contract cannot be paused.
7. `set_owner` is also gated by `require_owner_only` → cannot correct the owner. The engine is permanently unmanageable.

**Scenario B — Ownership transfer mistake:**

1. Current owner calls `set_owner` with `new_owner = "new-team.near"` (account not yet created on-chain).
2. `set_owner` passes `require_owner_only`, passes `ERR_SAME_OWNER` check, writes `"new-team.near"` to state.
3. The account `"new-team.near"` is never created, or is created by a different party.
4. All owner-gated functions are permanently inaccessible to the legitimate team.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
