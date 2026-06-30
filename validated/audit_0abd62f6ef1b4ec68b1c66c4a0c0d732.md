### Title
Single-Step Ownership Transfer with No Recipient Confirmation Enables Permanent Loss of `owner_id` - (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

The `set_owner` function in Aurora Engine performs an immediate, single-step ownership transfer to any syntactically valid NEAR `AccountId` without requiring confirmation from the new owner or verifying that the target account exists on-chain. If the current owner mistakenly transfers ownership to a non-existent or inaccessible account, the `owner_id` role is permanently and irrecoverably lost. Because every critical administrative function — including `pause_contract`, `resume_contract`, `pause_precompiles`, `set_upgrade_delay_blocks`, and `set_key_manager` — is gated exclusively behind `require_owner_only`, permanent loss of `owner_id` permanently disables the engine's emergency stop capability, making it impossible to halt an active exploit draining user funds.

---

### Finding Description

`set_owner` in `engine/src/contract_methods/admin.rs` (lines 103–121) performs an unconditional, immediate write of `args.new_owner` into `EngineState.owner_id`:

```rust
pub fn set_owner<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;

        let args: SetOwnerArgs = io.read_input_borsh()?;
        if state.owner_id == args.new_owner {
            return Err(errors::ERR_SAME_OWNER.into());
        }

        state.owner_id = args.new_owner;   // ← immediate, irreversible
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
``` [1](#0-0) 

The only validation applied to `new_owner` is the syntactic `AccountId` format check (2–64 chars, valid character set) enforced at deserialization time. [2](#0-1) 

There is **no**:
- Two-step propose-and-accept pattern
- On-chain existence check for the new owner account
- Rollback or time-lock window

The `EngineState.owner_id` field is the sole holder of the admin role: [3](#0-2) 

The `new()` initializer is protected against re-initialization:

```rust
if state::get_state(&io).is_ok() {
    return Err(b"ERR_ALREADY_INITIALIZED".into());
}
``` [4](#0-3) 

So there is no recovery path within the contract once `owner_id` is set to an inaccessible account.

Every critical administrative function is gated exclusively by `require_owner_only`: [5](#0-4) 

This includes `pause_contract` and `resume_contract`: [6](#0-5) 

A compounding issue: `set_owner` itself requires `require_running` (line 108), meaning if the contract is ever paused and the owner is simultaneously lost, the contract is permanently frozen — `resume_contract` also requires `require_owner_only` and there is no other actor who can call it. [7](#0-6) 

---

### Impact Explanation

**Critical — Permanent freezing of funds / inability to stop active theft.**

If `owner_id` is permanently lost:

1. `pause_contract` can never be called. If an exploit is actively draining user ETH or bridged ERC-20 balances, there is no emergency stop. Funds are stolen without recourse.
2. `resume_contract` can never be called. If the contract is in a paused state (e.g., paused before the owner was lost), all user funds locked in the engine are permanently frozen.
3. `pause_precompiles` / `resume_precompiles` can never be called, disabling the ability to isolate a compromised precompile.
4. `set_upgrade_delay_blocks` and contract upgrade flows are permanently blocked, preventing any patch deployment.

The ETH connector and bridged token balances held by the engine contract are the directly at-risk assets.

---

### Likelihood Explanation

**Medium.** The owner is a single NEAR account. A one-character typo in a NEAR account ID (e.g., `aurora.near` vs `auroa.near`) produces a syntactically valid `AccountId` that passes all contract-level checks but corresponds to a non-existent account. The operation is irreversible with a single transaction and no confirmation step. Operational mistakes of this class are well-documented in production deployments of single-step ownership transfer patterns across the industry. No attacker action is required — the owner alone triggers the loss.

---

### Recommendation

Replace the single-step transfer with a two-step propose-and-accept pattern:

1. The current owner calls `propose_new_owner(new_owner: AccountId)`, which stores a pending owner in state but does **not** update `owner_id`.
2. The proposed new owner calls `accept_ownership()`, which verifies `predecessor_account_id == pending_owner` and then writes the new `owner_id`.

This ensures the new owner account is live and accessible before the transfer is finalized. Additionally, remove the `require_running` guard from `set_owner` (or the equivalent `propose_new_owner`) so that ownership can be recovered even when the contract is paused.

---

### Proof of Concept

1. Current owner (`aurora.near`) calls `set_owner` with `new_owner = "auroa.near"` (typo — account does not exist on NEAR).
2. `set_owner` passes all checks: `require_running` (contract is running), `require_owner_only` (caller is current owner), `AccountId::validate` (syntactically valid), `owner_id != new_owner` (different string).
3. `state.owner_id` is written as `"auroa.near"` and persisted.
4. No account on NEAR can now satisfy `require_owner_only`, because `"auroa.near"` has no keys and cannot sign transactions.
5. Any subsequent call to `pause_contract`, `resume_contract`, `pause_precompiles`, `set_upgrade_delay_blocks`, or `set_key_manager` reverts with `ERR_NOT_ALLOWED`.
6. If a bridge exploit begins draining ETH balances, the engine cannot be paused. All user funds are at risk with no recovery mechanism within the contract.

### Citations

**File:** engine/src/contract_methods/admin.rs (L56-58)
```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
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

**File:** engine/src/contract_methods/admin.rs (L251-272)
```rust
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

**File:** engine-types/src/account_id.rs (L32-64)
```rust
    pub fn validate(account_id: &str) -> Result<(), ParseAccountError> {
        if account_id.len() < MIN_ACCOUNT_ID_LEN {
            Err(ParseAccountError::TooShort)
        } else if account_id.len() > MAX_ACCOUNT_ID_LEN {
            Err(ParseAccountError::TooLong)
        } else {
            // Adapted from https://github.com/near/near-sdk-rs/blob/fd7d4f82d0dfd15f824a1cf110e552e940ea9073/near-sdk/src/environment/env.rs#L819

            // NOTE: We don't want to use Regex here, because it requires extra time to compile it.
            // The valid account ID regex is /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/
            // Instead the implementation is based on the previous character checks.

            // We can safely assume that last char was a separator.
            let mut last_char_is_separator = true;

            for c in account_id.bytes() {
                let current_char_is_separator = match c {
                    b'a'..=b'z' | b'0'..=b'9' => false,
                    b'-' | b'_' | b'.' => true,
                    _ => {
                        return Err(ParseAccountError::Invalid);
                    }
                };
                if current_char_is_separator && last_char_is_separator {
                    return Err(ParseAccountError::Invalid);
                }
                last_char_is_separator = current_char_is_separator;
            }

            (!last_char_is_separator)
                .then_some(())
                .ok_or(ParseAccountError::Invalid)
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
