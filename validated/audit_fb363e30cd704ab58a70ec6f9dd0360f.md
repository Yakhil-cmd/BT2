I have all the information needed. Let me now write the finding.

---

### Title
Single-Step `set_owner` Transfers Ownership Immediately, Enabling Permanent Protocol Freeze - (File: `engine/src/contract_methods/admin.rs`)

### Summary
The Aurora Engine's `set_owner` function transfers `owner_id` in a single atomic step with no confirmation from the new owner. If the owner mistakenly supplies a wrong or uncontrolled NEAR account ID, all owner-gated functions — including `resume_contract` — become permanently inaccessible. Because `resume_contract` is the only way to unpause the engine, a paused engine with a lost owner results in permanent freezing of all user funds held in the EVM.

### Finding Description
`set_owner` in `engine/src/contract_methods/admin.rs` reads the caller-supplied `new_owner` from input and immediately overwrites `state.owner_id`:

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

        state.owner_id = args.new_owner;   // ← immediate, irrevocable
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

There is no "pending owner" stage and no acceptance call from the new owner. The only guard is a same-owner check. Once `state.owner_id` is written to storage, the old owner has no recourse.

`require_owner_only` enforces strict equality:

```rust
// engine/src/contract_methods/mod.rs, lines 79-87
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

Every critical administrative function gates on this check:

| Function | Effect if owner is lost |
|---|---|
| `resume_contract` | Contract stays paused forever |
| `pause_contract` | Cannot pause in an emergency |
| `upgrade` / `stage_upgrade` | Contract cannot be patched |
| `resume_precompiles` | Paused precompiles stay paused |
| `set_eth_connector_contract_account` | Bridge connector cannot be updated |
| `factory_update` | XCC router cannot be updated |
| `attach_full_access_key` | No recovery key can be added |

The `EngineState` struct stores `owner_id` as the sole authority field with no fallback:

```rust
// engine/src/state.rs, lines 18-31
pub struct EngineState {
    pub chain_id: [u8; 32],
    pub owner_id: AccountId,          // sole owner, no pending_owner
    pub upgrade_delay_blocks: u64,
    pub is_paused: bool,
    pub key_manager: Option<AccountId>,
}
```

### Impact Explanation
**Critical — Permanent freezing of funds.**

The concrete path to fund freeze:

1. The engine is paused (legitimately, e.g., for a security incident or upgrade).
2. The owner calls `set_owner` with a typo or a decommissioned account ID.
3. `state.owner_id` is immediately overwritten.
4. `resume_contract` requires `require_owner_only`, which now fails for every real account.
5. The engine remains paused permanently.
6. All EVM balances — ETH and ERC-20 tokens bridged via the connector — are frozen with no recovery path.

Even without a prior pause, the loss of the owner permanently removes the ability to call `upgrade`, meaning any future critical bug cannot be patched, and the ability to call `resume_precompiles` or `set_eth_connector_contract_account`, which can indirectly freeze bridge flows.

### Likelihood Explanation
**Low.** Exploitation requires the current owner to supply an incorrect `new_owner` account ID — a typo, a decommissioned multisig, or a staging account. This is an operational error, not an external attack. The likelihood matches the original report's assessment exactly.

### Recommendation
Adopt the two-step ownership transfer pattern:

1. Add a `pending_owner: Option<AccountId>` field to `EngineState`.
2. `set_owner` writes only to `pending_owner`, not to `owner_id`.
3. Add an `accept_owner` function that requires `predecessor_account_id == pending_owner` and then promotes `pending_owner` to `owner_id`.

This ensures the new owner can demonstrably sign a transaction before the transfer is finalised, making it impossible to accidentally transfer ownership to an uncontrolled account.

The same pattern should be applied to `set_key_manager` in `engine/src/contract_methods/admin.rs` (lines 274–296), which also performs a single-step transfer of the `key_manager` role.

### Proof of Concept

**Scenario: owner transferred to wrong address while contract is paused**

```
1. Current owner calls pause_contract → state.is_paused = true
   (All EVM transactions now fail with ERR_PAUSED)

2. Current owner calls set_owner with args:
   SetOwnerArgs { new_owner: "typo-account.near" }
   → state.owner_id = "typo-account.near"  (irrevocable)

3. Current owner attempts resume_contract:
   require_owner_only(&state, "real-owner.near")
   → "real-owner.near" != "typo-account.near"
   → ERR_NOT_ALLOWED

4. "typo-account.near" does not exist / is not controlled by anyone.
   → resume_contract can never succeed.
   → state.is_paused remains true forever.
   → All user ETH and ERC-20 balances in the Aurora EVM are permanently frozen.
```

Relevant code locations:
- `set_owner`: `engine/src/contract_methods/admin.rs`, lines 103–121 [1](#0-0) 
- `resume_contract` (owner-gated): `engine/src/contract_methods/admin.rs`, lines 262–272 [2](#0-1) 
- `require_owner_only`: `engine/src/contract_methods/mod.rs`, lines 79–87 [3](#0-2) 
- `EngineState.owner_id` (no `pending_owner` field): `engine/src/state.rs`, lines 18–31 [4](#0-3) 
- Public WASM entrypoint: `engine/src/lib.rs`, lines 103–111 [5](#0-4)

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

**File:** engine/src/lib.rs (L103-111)
```rust
    /// Set owner account id for this contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn set_owner() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::set_owner(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
